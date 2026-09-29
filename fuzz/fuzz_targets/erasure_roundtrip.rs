// SPDX-License-Identifier: CC-BY-NC-SA-4.0
#![no_main]

use kagi_object_store::erasure::{
    AdaptiveBackend, BackendKind, ErasureBackend, ErasureConfig, ErasureLayout, ErasureScheme,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("fuzz runtime")
    })
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 4 {
        return;
    }

    let scheme = match input[0] % 3 {
        0 => ErasureScheme::ReedSolomon,
        1 => ErasureScheme::Clay,
        _ => ErasureScheme::Msr,
    };
    let k = 1 + input[1] as usize % 8;
    let m = 1 + input[2] as usize % 8;
    let layout = ErasureLayout {
        scheme,
        data_shards: k,
        parity_shards: m,
        repair_helpers: None,
    };
    if layout.validate().is_err() {
        return;
    }

    // Keep each libFuzzer iteration bounded while still covering padding, tails,
    // matrix dimensions and reconstruction with arbitrary bytes.
    let data = &input[3..input.len().min(64 * 1024 + 3)];
    let backend = AdaptiveBackend::new(ErasureConfig {
        backend: BackendKind::Cpu,
        scheme,
        data_shards: k,
        parity_shards: m,
        repair_helpers: None,
        gpu_threshold_bytes: usize::MAX,
        ..ErasureConfig::default()
    });

    runtime().block_on(async {
        let Ok(encoded) = backend.encode_layout(data, &layout).await else {
            return;
        };
        if encoded.shards.is_empty() {
            panic!("valid layout encoded zero shards");
        }
        let lost = input[3] as usize % encoded.shards.len();
        let original_len = encoded.original_len;
        let mut shards = encoded.shards.into_iter().map(Some).collect::<Vec<_>>();
        shards[lost] = None;
        let rebuilt = backend
            .reconstruct_layout(&mut shards, original_len, &layout)
            .await
            .expect("valid single-shard reconstruction");
        assert_eq!(rebuilt, data);
    });
});
