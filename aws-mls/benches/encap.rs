use aws_mls::{
    bench_utils::create_empty_tree::{load_test_cases, TestCase},
    cipher_suite::CipherSuite,
    extension::{ExtensionList, LeafNodeExtension},
    provider::{crypto::test_utils::test_cipher_suite_provider, identity::BasicIdentityProvider},
    tree_kem::{
        kem::TreeKem,
        leaf_node::{test_utils::get_test_capabilities, ConfigProperties},
        node::LeafIndex,
        Capabilities,
    },
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use std::collections::HashMap;

fn encap_setup(c: &mut Criterion) {
    let mut encap_group = c.benchmark_group("encap");

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking encap for: {cipher_suite:?}");

    let trees = load_test_cases();

    bench_encap(&mut encap_group, &[], None, None, cipher_suite, trees);

    encap_group.finish();
}

fn bench_encap(
    bench_group: &mut BenchmarkGroup<WallTime>,
    excluding: &[LeafIndex],
    capabilities: Option<Capabilities>,
    extensions: Option<ExtensionList<LeafNodeExtension>>,
    cipher_suite: CipherSuite,
    map: HashMap<usize, TestCase>,
) {
    for (key, mut value) in map {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            &key,
            |b, _| {
                b.iter(|| {
                    let update_leaf_properties = ConfigProperties {
                        capabilities: capabilities.clone().unwrap_or_else(get_test_capabilities),
                        extensions: extensions.clone().unwrap_or_default(),
                    };

                    TreeKem::new(&mut value.encap_tree, &mut value.encap_private_key)
                        .encap(
                            &mut value.group_context,
                            excluding,
                            &value.encap_signer,
                            update_leaf_properties,
                            None,
                            BasicIdentityProvider,
                            &test_cipher_suite_provider(cipher_suite),
                        )
                        .unwrap()
                })
            },
        );
    }
}

criterion_group!(benches, encap_setup);
criterion_main!(benches);