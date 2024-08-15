// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs::MlsMessage;
use mls_rs::{
    client_builder::MlsConfig,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
};

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

fn make_client<P: CryptoProvider + Clone>(
    crypto_provider: P,
    name: &str,
) -> anyhow::Result<Client<impl MlsConfig>> {
    let cipher_suite = crypto_provider.cipher_suite_provider(CIPHERSUITE).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    // Create a basic credential for the session.
    // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
    // X.509 credentials are recommended.
    let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider)
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .build())
}

fn print_group(group: &mls_rs::Group<impl MlsConfig>, name: &str) {
    println!(
        "{name} sees these members, current epoch {}:",
        group.current_epoch()
    );
    for member in group.roster().members_iter() {
        let identifier = &member
            .signing_identity
            .credential
            .as_basic()
            .unwrap()
            .identifier;
        println!("- {:?}", String::from_utf8_lossy(&identifier));
    }
}

fn main() -> anyhow::Result<()> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let alice = make_client(crypto_provider.clone(), "alice")?;

    println!("Alice creates a new group");
    let mut alice_group = alice.create_group(ExtensionList::default())?;

    /*
    println!("Bob generates a key package");
    let bob = make_client(crypto_provider.clone(), "bob")?;
    let bob_key_package = bob.generate_key_package_message()?;
    eprintln!("{:?}", hex::encode(bob_key_package.to_bytes()?));
     */
    let bob_key_package_bytes = b"000100050001000120cd5953845bd1ebe083ca3b9b90a224d75b814d83e5524bc36973b55ddaa4703120ffce824f35eda0b34a9c1a59c142a5793e58227f6ca699f22b6ebfaabfef1f1a2052972e50fa11e98925a9a446b06963f0e429fb52643d1fa6fdb57d846d05ce4e000103626f620200010e00010002000300040005000600070000020001010000000066be005000000000689f33d00040406aa6797ee92aa0fd0fc5d02aeab5b5a7e89efc8e100434cc8f8f371c57f62a1738824796e96fa181de85a71a5f8037a8d762f3c41f77580010c889af4639060d00404008cc725f5efd40a2316eb107f5ae6bfbcdfe747da199314abe60ff388cb87fc29e10ce41d7f8b5c8da489c91ab99cd3cf0d7d45f2d0295a717f45f9fcbb13f0d";
    let bob_key_package = MlsMessage::from_bytes(&hex::decode(bob_key_package_bytes)?)?;

    println!("Alice adds Bob to the group");
    alice_group
        .commit_builder()
        .add_member(bob_key_package.clone())?
        .build()?;
    alice_group.apply_pending_commit()?;
    print_group(&alice_group, "Alice");

    println!("Alice writes to the group");
    alice_group.encrypt_application_message(b"hello world", Default::default())?;

    println!("Alice writes to storage");
    alice_group.write_to_storage()?;

    println!("Alice removes Bob");
    let bob_idx = alice_group.member_with_identity(b"bob")?.index;
    alice_group
        .commit_builder()
        .remove_member(bob_idx)?
        .build()?;
    alice_group.apply_pending_commit()?;
    print_group(&alice_group, "Alice");

    println!("Alice adds Bob again");
    alice_group
        .commit_builder()
        .add_member(bob_key_package)?
        .build()?;
    alice_group.apply_pending_commit()?;
    print_group(&alice_group, "Alice");

    println!("Alice writes to the group again");
    alice_group.encrypt_application_message(b"hello again", Default::default())?;

    Ok(())
}
