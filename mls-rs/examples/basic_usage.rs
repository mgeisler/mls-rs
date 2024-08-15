// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use anyhow::Context;
use mls_rs::group::ReceivedMessage;
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
    println!("{name} sees these members:");
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

fn add_member(
    old_group: &mut mls_rs::Group<impl MlsConfig>,
    client: &mls_rs::Client<impl MlsConfig>,
    key_package: mls_rs::MlsMessage,
) -> anyhow::Result<mls_rs::Group<impl MlsConfig>> {
    let commit = old_group
        .commit_builder()
        .add_member(key_package)
        .context("Adding member")?
        .build()
        .context("Building")?;
    old_group
        .apply_pending_commit()
        .context("Applying pending commit")?;

    let (new_group, _) = client
        .join_group(None, &commit.welcome_messages[0])
        .context("Joining new group")?;
    Ok(new_group)
}

fn main() -> anyhow::Result<()> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();

    // Create clients for Alice and Bob
    let alice = make_client(crypto_provider.clone(), "alice")?;
    let bob = make_client(crypto_provider.clone(), "bob")?;

    println!("Alice creates a new group");
    let mut alice_group = alice.create_group(ExtensionList::default())?;

    /*
    println!("Bob generates a key package");
    let bob_key_package = bob.generate_key_package_message()?;
    eprintln!("{:?}", hex::encode(bob_key_package.to_bytes()?));
     */
    let bob_key_package_bytes = b"000100050001000120cd5953845bd1ebe083ca3b9b90a224d75b814d83e5524bc36973b55ddaa4703120ffce824f35eda0b34a9c1a59c142a5793e58227f6ca699f22b6ebfaabfef1f1a2052972e50fa11e98925a9a446b06963f0e429fb52643d1fa6fdb57d846d05ce4e000103626f620200010e00010002000300040005000600070000020001010000000066be005000000000689f33d00040406aa6797ee92aa0fd0fc5d02aeab5b5a7e89efc8e100434cc8f8f371c57f62a1738824796e96fa181de85a71a5f8037a8d762f3c41f77580010c889af4639060d00404008cc725f5efd40a2316eb107f5ae6bfbcdfe747da199314abe60ff388cb87fc29e10ce41d7f8b5c8da489c91ab99cd3cf0d7d45f2d0295a717f45f9fcbb13f0d";
    let bob_key_package = MlsMessage::from_bytes(&hex::decode(bob_key_package_bytes)?)?;

    println!("Alice adds Bob to her group");
    let mut bob_group = add_member(&mut alice_group, &bob, bob_key_package.clone())?;

    let msg = alice_group.encrypt_application_message(b"hello world", Default::default())?;

    match bob_group.process_incoming_message(msg)? {
        ReceivedMessage::ApplicationMessage(msg) => {
            println!("Received message: {:?}", std::str::from_utf8(msg.data()))
        }
        msg => panic!("Expected ApplicationMessage, got {msg:?}"),
    }

    println!("Writing to storage");
    alice_group.write_to_storage()?;
    bob_group.write_to_storage()?;

    print_group(&alice_group, "Alice");
    print_group(&bob_group, "Bob");

    let bob_idx = alice_group.member_with_identity(b"bob")?.index;
    let remove_bob_commit = alice_group
        .commit_builder()
        .remove_member(bob_idx)?
        .build()?;

    println!("Alice removes Bob");
    alice_group.apply_pending_commit()?;
    bob_group.process_incoming_message(remove_bob_commit.commit_message)?;

    println!("Group epochs after removing Bob:");
    dbg!(alice_group.current_epoch(), bob_group.current_epoch());

    println!("Alice has removed Bob, Bob no longer participates in the group");
    print_group(&alice_group, "Alice");
    print_group(&bob_group, "Bob");

    let bob_group2 =
        add_member(&mut alice_group, &bob, bob_key_package).context("Adding Bob again")?;

    println!("Alice adds Bob again:");
    print_group(&alice_group, "Alice");
    print_group(&bob_group2, "Bob");

    Ok(())
}
