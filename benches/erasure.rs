// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Criterion microbenchmarks for Kagi's compute data path.
//!
//! The operator-facing kagi-bench binary provides reproducible reports. This harness
//! exists for regression tracking, local profiling, and Criterion statistics.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kagi_object_store::erasure::{
    AdaptiveBackend, BackendKind, ErasureBackend, ErasureConfig, ErasureLayout, ErasureScheme,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn data(bytes: usize) -> Vec<u8> {
    let mut output = vec![0u8; bytes];
    ChaCha20Rng::seed_from_u64(0x4b414749 ^ bytes as u64).fill_bytes(&mut output);
    output
}

fn bench_scheme(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    runtime: &tokio::runtime::Runtime,
    scheme: ErasureScheme,
    k: usize,
    m: usize,
    bytes: usize,
) {
    let input = data(bytes);
    let layout = ErasureLayout {
        scheme,
        data_shards: k,
        parity_shards: m,
        repair_helpers: None,
    };
    layout.validate().unwrap();
    let backend = AdaptiveBackend::new(ErasureConfig {
        backend: BackendKind::Cpu,
        scheme,
        data_shards: k,
        parity_shards: m,
        repair_helpers: None,
        gpu_threshold_bytes: usize::MAX,
        ..ErasureConfig::default()
    });

    group.throughput(Throughput::Bytes(bytes as u64));
    group.bench_with_input(
        BenchmarkId::new(format!("{scheme:?}-{k}+{m}"), bytes),
        &input,
        |bench, input| {
            bench.iter(|| {
                runtime
                    .block_on(backend.encode_layout(black_box(input), &layout))
                    .unwrap()
            })
        },
    );
}

fn erasure_encode(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("erasure_encode");
    for bytes in [1 << 20, 8 << 20] {
        bench_scheme(
            &mut group,
            &runtime,
            ErasureScheme::ReedSolomon,
            6,
            3,
            bytes,
        );
        bench_scheme(&mut group, &runtime, ErasureScheme::Clay, 6, 3, bytes);
        bench_scheme(&mut group, &runtime, ErasureScheme::Msr, 4, 4, bytes);
    }
    group.finish();
}

fn blake3_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_baseline");
    for bytes in [1 << 20, 8 << 20, 64 << 20] {
        let input = data(bytes);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(bytes),
            &input,
            |bench, input| {
                bench.iter(|| blake3::hash(black_box(input)));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, erasure_encode, blake3_baseline);
criterion_main!(benches);
