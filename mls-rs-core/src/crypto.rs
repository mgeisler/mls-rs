// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::error::IntoAnyError;
use alloc::vec;
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug},
    ops::Deref,
};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

mod cipher_suite;
pub use self::cipher_suite::*;

#[cfg(feature = "test_suite")]
pub mod test_suite;

#[derive(Clone, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
/// Ciphertext produced by [`CipherSuiteProvider::hpke_seal`]
pub struct HpkeCiphertext {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    pub kem_output: Vec<u8>,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    pub ciphertext: Vec<u8>,
}

impl Debug for HpkeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeCiphertext")
            .field("kem_output", &crate::debug::pretty_bytes(&self.kem_output))
            .field("ciphertext", &crate::debug::pretty_bytes(&self.ciphertext))
            .finish()
    }
}

/// Byte representation of an HPKE public key. For ciphersuites using elliptic curves,
/// the public key should be represented in the uncompressed format.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, MlsSize, MlsDecode, MlsEncode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HpkePublicKey(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    Vec<u8>,
);

impl Debug for HpkePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::debug::pretty_bytes(&self.0)
            .named("HpkePublicKey")
            .fmt(f)
    }
}

impl From<Vec<u8>> for HpkePublicKey {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl From<HpkePublicKey> for Vec<u8> {
    fn from(data: HpkePublicKey) -> Self {
        data.0
    }
}

impl Deref for HpkePublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HpkePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Byte representation of an HPKE secret key.
#[derive(Clone, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, ZeroizeOnDrop)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HpkeSecretKey(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    Vec<u8>,
);

impl Debug for HpkeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::debug::pretty_bytes(&self.0)
            .named("HpkeSecretKey")
            .fmt(f)
    }
}

impl From<Vec<u8>> for HpkeSecretKey {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Deref for HpkeSecretKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HpkeSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The HPKE context for sender outputted by [hpke_setup_s](CipherSuiteProvider::hpke_setup_s).
/// The context internally stores the secrets generated by [hpke_setup_s](CipherSuiteProvider::hpke_setup_s).
///
/// This trait corresponds to ContextS from RFC 9180.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
pub trait HpkeContextS {
    type Error: IntoAnyError;

    /// Encrypt `data` using the cipher key of the context with optional `aad`.
    /// This function should internally increment the sequence number.
    async fn seal(&mut self, aad: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Export a secret from the context for the given `exporter_context`.
    async fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error>;
}

/// The HPKE context for receiver outputted by [hpke_setup_r](CipherSuiteProvider::hpke_setup_r).
/// The context internally stores secrets received from the sender by [hpke_setup_r](CipherSuiteProvider::hpke_setup_r).
///
/// This trait corresponds to ContextR from RFC 9180.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
pub trait HpkeContextR {
    type Error: IntoAnyError;

    /// Decrypt `ciphertext` using the cipher key of the context with optional `aad`.
    /// This function should internally increment the sequence number.
    async fn open(&mut self, aad: Option<&[u8]>, ciphertext: &[u8])
        -> Result<Vec<u8>, Self::Error>;

    /// Export a secret from the context for the given `exporter_context`.
    async fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error>;
}

/// Byte representation of a signature public key. For ciphersuites using elliptic curves,
/// the public key should be represented in the uncompressed format.
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(all(feature = "ffi", not(test)), ::safer_ffi_gen::ffi_type(opaque))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignaturePublicKey(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    Vec<u8>,
);

impl Debug for SignaturePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::debug::pretty_bytes(&self.0)
            .named("SignaturePublicKey")
            .fmt(f)
    }
}

#[cfg_attr(all(feature = "ffi", not(test)), ::safer_ffi_gen::safer_ffi_gen)]
impl SignaturePublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        bytes.into()
    }

    pub fn new_slice(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for SignaturePublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SignaturePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePublicKey {
    fn from(data: Vec<u8>) -> Self {
        SignaturePublicKey(data)
    }
}

impl From<SignaturePublicKey> for Vec<u8> {
    fn from(value: SignaturePublicKey) -> Self {
        value.0
    }
}

/// Byte representation of a signature key.
#[cfg_attr(
    all(feature = "ffi", not(test)),
    ::safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignatureSecretKey {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    bytes: Vec<u8>,
}

impl Debug for SignatureSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::debug::pretty_bytes(&self.bytes)
            .named("SignatureSecretKey")
            .fmt(f)
    }
}

#[cfg_attr(all(feature = "ffi", not(test)), ::safer_ffi_gen::safer_ffi_gen)]
impl SignatureSecretKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        bytes.into()
    }

    pub fn new_slice(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for SignatureSecretKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl Deref for SignatureSecretKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for SignatureSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Provides implementations for several ciphersuites via [`CipherSuiteProvider`].
pub trait CryptoProvider: Send + Sync {
    type CipherSuiteProvider: CipherSuiteProvider + Clone;

    /// Return the list of all supported ciphersuites.
    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;

    /// Generate a [CipherSuiteProvider] for the given `cipher_suite`.
    fn cipher_suite_provider(&self, cipher_suite: CipherSuite)
        -> Option<Self::CipherSuiteProvider>;
}

/// Provides all cryptographic operations required by MLS for a given cipher suite.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
pub trait CipherSuiteProvider: Send + Sync {
    type Error: IntoAnyError;

    type HpkeContextS: HpkeContextS + Send + Sync;
    type HpkeContextR: HpkeContextR + Send + Sync;

    /// Return the implemented MLS [CipherSuite](CipherSuite).
    fn cipher_suite(&self) -> CipherSuite;

    /// Compute the hash of `data`.
    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Compute the MAC tag of `data` using the `key` of length [kdf_extract_size](CipherSuiteProvider::kdf_extract_size).
    /// Verifying a MAC tag of `data` using `key` is done by calling this function
    /// and checking that the result matches the tag.
    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Encrypt `data` with public additional authenticated data `aad`, using additional `nonce`
    /// (sometimes called the initialization vector, IV). The output should include
    /// the authentication tag, if used by the given AEAD implementation (for example,
    /// the tag can be appended to the ciphertext).
    async fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt the `ciphertext` generated by [aead_seal](CipherSuiteProvider::aead_seal).
    /// This function should return an error if any of the inputs `key`, `aad` or `nonce` does not match
    /// the corresponding input passed to [aead_seal](CipherSuiteProvider::aead_seal) to generate `ciphertext`.
    async fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error>;

    /// Return the length of the secret key `key` passed to [aead_seal](CipherSuiteProvider::aead_seal)
    /// and [aead_open](CipherSuiteProvider::aead_open).
    fn aead_key_size(&self) -> usize;

    /// Return the length of the `nonce` passed to [aead_seal](CipherSuiteProvider::aead_seal)
    /// and [aead_open](CipherSuiteProvider::aead_open).
    fn aead_nonce_size(&self) -> usize;

    /// Generate a pseudo-random key `prk` extracted from the initial key
    /// material `ikm`, using an optional random `salt`. The outputted `prk` should have
    /// [kdf_extract_size](CipherSuiteProvider::kdf_extract_size) bytes. It can be used
    /// as input to [kdf_expand](CipherSuiteProvider::kdf_expand).
    ///
    /// This function corresponds to the HKDF-Extract function from RFC 5869.
    async fn kdf_extract(&self, salt: &[u8], ikm: &[u8])
        -> Result<Zeroizing<Vec<u8>>, Self::Error>;

    /// Generate key material of the desired length `len` by expanding the given pseudo-random key
    /// `prk` of length [kdf_extract_size](CipherSuiteProvider::kdf_extract_size).
    /// The additional input `info` contains optional context data.
    ///
    /// This function corresponds to the HKDF-Expand function from RFC 5869.
    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error>;

    /// Return the size of pseudo-random key `prk` outputted by [kdf_extract](CipherSuiteProvider::kdf_extract)
    /// and inputted to [kdf_expand](CipherSuiteProvider::kdf_expand).
    fn kdf_extract_size(&self) -> usize;

    /// Encrypt the plaintext `pt` with optional public additional authenticated data `aad` to the
    /// public key `remote_key` using additional context information `info` (which can be empty if
    /// not needed). This function combines the action
    /// of the [hpke_setup_s](CipherSuiteProvider::hpke_setup_s) and then calling [seal](HpkeContextS::seal)
    /// on the resulting [HpkeContextS](self::HpkeContextS).
    ///
    /// This function corresponds to the one-shot API in base mode in RFC 9180.
    async fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error>;

    /// Decrypt the `ciphertext` generated by [hpke_seal](CipherSuiteProvider::hpke_seal).
    /// This function combines the action of the [hpke_setup_r](CipherSuiteProvider::hpke_setup_r)
    /// and then calling [open](HpkeContextR::open) on the resulting [HpkeContextR](self::HpkeContextR).
    ///
    /// This function corresponds to the one-shot API in base mode in RFC 9180.
    async fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Generate a tuple containing the ciphertext `kem_output` that can
    /// be used as the input to [hpke_setup_r](CipherSuiteProvider::hpke_setup_r),
    /// as well as the sender context [HpkeContextS](self::HpkeContextS) that can be
    /// used to generate AEAD ciphertexts and export keys.
    ///
    /// The inputted `remote_key` will normally be generated using
    /// [kem_derive](CipherSuiteProvider::kem_derive) or
    /// [kem_generate](CipherSuiteProvider::kem_generate). However, the function
    /// should return an error if the format is incorrect.
    ///
    /// This function corresponds to the SetupBaseS function from RFC 9180.
    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error>;

    /// Receive the ciphertext `kem_output` generated by [hpke_setup_s](CipherSuiteProvider::hpke_setup_s)
    /// and the `local_secret` corresponding to the `remote_key` used as input to
    /// [hpke_setup_s](CipherSuiteProvider::hpke_setup_s). The ouput is the receiver context
    /// [HpkeContextR](self::HpkeContextR) that can be used to decrypt AEAD ciphertexts
    /// generated by the sender context [HpkeContextS](self::HpkeContextS) outputted by
    /// [hpke_setup_r](CipherSuiteProvider::hpke_setup_r)
    /// and export the same keys as that context.
    ///
    /// The inputted `local_secret` will normally be generated using
    /// [kem_derive](CipherSuiteProvider::kem_derive) or
    /// [kem_generate](CipherSuiteProvider::kem_generate). However, the function
    /// should return an error if the format is incorrect.
    ///
    /// This function corresponds to the SetupBaseR function from RFC 9180.
    async fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,

        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error>;

    /// Derive from the initial key material `ikm` the KEM keys used as inputs to
    /// [hpke_setup_r](CipherSuiteProvider::hpke_setup_r),
    /// [hpke_setup_s](CipherSuiteProvider::hpke_setup_s), [hpke_seal](CipherSuiteProvider::hpke_seal)
    /// and [hpke_open](CipherSuiteProvider::hpke_open).
    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    /// Generate fresh KEM keys to be used as inputs to [hpke_setup_r](CipherSuiteProvider::hpke_setup_r),
    /// [hpke_setup_s](CipherSuiteProvider::hpke_setup_s), [hpke_seal](CipherSuiteProvider::hpke_seal)
    /// and [hpke_open](CipherSuiteProvider::hpke_open).
    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    /// Verify that the given byte vector `key` can be decoded as an HPKE public key.
    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error>;

    /// Fill `out` with random bytes.
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error>;

    /// Generate `count` bytes of pseudorandom bytes as a vector. This is a shortcut for
    /// creating a `Vec<u8>` of `count` bytes and calling [random_bytes](CipherSuiteProvider::random_bytes).
    fn random_bytes_vec(&self, count: usize) -> Result<Vec<u8>, Self::Error> {
        let mut vec = vec![0u8; count];
        self.random_bytes(&mut vec)?;

        Ok(vec)
    }

    /// Generate fresh signature keys to be used as inputs to [sign](CipherSuiteProvider::sign)
    /// and [verify](CipherSuiteProvider::verify)
    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error>;

    /// Output a public key corresponding to `secret_key`.
    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error>;

    /// Sign `data` using `secret_key`.
    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Verify that the secret key corresponding to `public_key` created the `signature` over `data`.
    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error>;
}
