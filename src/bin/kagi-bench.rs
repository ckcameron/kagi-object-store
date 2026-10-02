// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Reproducible local performance/demo harness for Kagi's compute data path.
//!
//! This is intentionally not a storage stress/destructive benchmark. It measures the
//! immutable-object coding path in memory, verifies reconstruction correctness on every
//! sample, reports backend dispatch counters, and emits machine-readable JSON for comparing
//! CPU/GPU/compiler configurations. Use external fio/perf tooling for device benchmarking.

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use kagi_object_store::erasure::{
    AdaptiveBackend, BackendKind, ErasureBackend, ErasureConfig, ErasureLayout, ErasureScheme,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchBackend {
    Auto,
    Cpu,
    Cuda,
    Hip,
    Opencl,
}

impl From<BenchBackend> for BackendKind {
    fn from(value: BenchBackend) -> Self {
        match value {
            BenchBackend::Auto => BackendKind::Auto,
            BenchBackend::Cpu => BackendKind::Cpu,
            BenchBackend::Cuda => BackendKind::Cuda,
            BenchBackend::Hip => BackendKind::Hip,
            BenchBackend::Opencl => BackendKind::Opencl,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchScheme {
    ReedSolomon,
    Lrc,
    Clay,
    Msr,
    All,
}

#[derive(Parser, Debug)]
#[command(
    name = "kagi-bench",
    version,
    about = "Kagi compute/performance analysis demo"
)]
struct Args {
    /// Backend requested for erasure operations. Unavailable GPU backends may fall back to CPU.
    #[arg(long, value_enum, default_value_t = BenchBackend::Auto)]
    backend: BenchBackend,

    /// Codec family to benchmark.
    #[arg(long, value_enum, default_value_t = BenchScheme::All)]
    scheme: BenchScheme,

    /// Comma-separated payload sizes. Accepts B, KiB/MiB/GiB and K/M/G suffixes.
    #[arg(long, default_value = "1MiB,8MiB,64MiB")]
    sizes: String,

    /// Timed repetitions per size after warmup.
    #[arg(long, default_value_t = 5)]
    iterations: usize,

    /// Optional data-shard override. Defaults are representative and scheme-specific.
    #[arg(long)]
    data_shards: Option<usize>,

    /// Optional parity-shard override.
    #[arg(long)]
    parity_shards: Option<usize>,

    /// GPU dispatch threshold in bytes.
    #[arg(long, default_value_t = 1 << 20)]
    gpu_threshold_bytes: usize,

    /// Deterministic payload seed.
    #[arg(long, default_value_t = 0x4b414749)]
    seed: u64,

    /// Write the complete report to JSON as well as printing a concise table.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Fail unless the requested GPU backend is available, executes, and completes without fallback.
    #[arg(long)]
    require_acceleration: bool,
}

#[derive(Debug, Serialize)]
struct Environment {
    unix_ms: u128,
    os: String,
    arch: String,
    cpu_threads: usize,
    rust_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct Sample {
    scheme: ErasureScheme,
    backend_requested: BackendKind,
    bytes: usize,
    data_shards: usize,
    parity_shards: usize,
    encode_mib_s: f64,
    reconstruct_mib_s: f64,
    encode_p50_ms: f64,
    encode_p95_ms: f64,
    reconstruct_p50_ms: f64,
    reconstruct_p95_ms: f64,
}

#[derive(Debug, Serialize)]
struct Report {
    product: &'static str,
    version: &'static str,
    environment: Environment,
    acceleration: serde_json::Value,
    metrics: serde_json::Value,
    samples: Vec<Sample>,
}

fn parse_size(input: &str) -> Result<usize> {
    let value = input.trim();
    if value.is_empty() {
        bail!("empty benchmark size");
    }
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let number: f64 = value[..split].parse()?;
    let suffix = value[split..].trim().to_ascii_lowercase();
    let factor = match suffix.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "kib" => 1024.0,
        "m" | "mb" => 1_000_000.0,
        "mib" => 1024.0 * 1024.0,
        "g" | "gb" => 1_000_000_000.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        _ => bail!("unsupported size suffix {suffix}"),
    };
    let bytes = number * factor;
    if !bytes.is_finite() || bytes < 1.0 || bytes > usize::MAX as f64 {
        bail!("invalid benchmark size {input}");
    }
    Ok(bytes.round() as usize)
}

fn schemes(selection: BenchScheme) -> Vec<ErasureScheme> {
    match selection {
        BenchScheme::ReedSolomon => vec![ErasureScheme::ReedSolomon],
        BenchScheme::Clay => vec![ErasureScheme::Clay],
        BenchScheme::Msr => vec![ErasureScheme::Msr],
        BenchScheme::Lrc => vec![ErasureScheme::Lrc],
        BenchScheme::All => vec![
            ErasureScheme::ReedSolomon,
            ErasureScheme::Lrc,
            ErasureScheme::Clay,
            ErasureScheme::Msr,
        ],
    }
}

fn default_geometry(
    scheme: ErasureScheme,
    k_override: Option<usize>,
    m_override: Option<usize>,
) -> (usize, usize) {
    let (k, m) = match scheme {
        ErasureScheme::ReedSolomon | ErasureScheme::Clay | ErasureScheme::Lrc => (6, 3),
        // Product-matrix MSR requires n > d=2k-2. 4+4 gives d=6,n=8.
        ErasureScheme::Msr => (4, 4),
    };
    (k_override.unwrap_or(k), m_override.unwrap_or(m))
}

fn percentile(samples: &[Duration], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut micros = samples
        .iter()
        .map(|sample| sample.as_secs_f64() * 1_000_000.0)
        .collect::<Vec<_>>();
    micros.sort_by(f64::total_cmp);
    let index = ((micros.len() - 1) as f64 * percentile)
        .round()
        .clamp(0.0, (micros.len() - 1) as f64) as usize;
    micros[index] / 1_000.0
}

fn mib_per_second(bytes: usize, samples: &[Duration]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let seconds = samples.iter().map(Duration::as_secs_f64).sum::<f64>() / samples.len() as f64;
    if seconds <= 0.0 {
        0.0
    } else {
        (bytes as f64 / (1024.0 * 1024.0)) / seconds
    }
}

fn rust_version() -> Option<String> {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[derive(Debug, Clone, Copy)]
struct BenchRun {
    iterations: usize,
    gpu_threshold_bytes: usize,
    seed: u64,
}

async fn bench_one(
    backend_kind: BackendKind,
    scheme: ErasureScheme,
    bytes: usize,
    k: usize,
    m: usize,
    run: BenchRun,
) -> Result<(Sample, AdaptiveBackend)> {
    let layout = ErasureLayout {
        scheme,
        data_shards: k,
        parity_shards: m,
        repair_helpers: None,
    };
    layout.validate()?;

    let backend = AdaptiveBackend::new(ErasureConfig {
        backend: backend_kind,
        scheme,
        data_shards: k,
        parity_shards: m,
        repair_helpers: None,
        gpu_threshold_bytes: run.gpu_threshold_bytes,
        ..ErasureConfig::default()
    });

    let mut input = vec![0u8; bytes];
    ChaCha20Rng::seed_from_u64(run.seed ^ bytes as u64 ^ ((k as u64) << 32) ^ m as u64)
        .fill_bytes(&mut input);

    // Untimed warmup catches invalid layouts/backends and primes lazy runtime setup.
    let warm = backend.encode_layout(&input, &layout).await?;
    let mut warm_shards = warm.shards.into_iter().map(Some).collect::<Vec<_>>();
    warm_shards[0] = None;
    let rebuilt = backend
        .reconstruct_layout(&mut warm_shards, warm.original_len, &layout)
        .await?;
    anyhow::ensure!(rebuilt == input, "warmup reconstruction mismatch");

    let mut encode_times = Vec::with_capacity(run.iterations);
    let mut reconstruct_times = Vec::with_capacity(run.iterations);

    for iteration in 0..run.iterations {
        let start = Instant::now();
        let encoded = backend.encode_layout(&input, &layout).await?;
        encode_times.push(start.elapsed());

        let mut shards = encoded.shards.into_iter().map(Some).collect::<Vec<_>>();
        let lost = iteration % shards.len();
        shards[lost] = None;
        let start = Instant::now();
        let rebuilt = backend
            .reconstruct_layout(&mut shards, encoded.original_len, &layout)
            .await?;
        reconstruct_times.push(start.elapsed());
        anyhow::ensure!(
            rebuilt == input,
            "reconstruction mismatch for {:?} iteration {iteration}",
            scheme
        );
    }

    Ok((
        Sample {
            scheme,
            backend_requested: backend_kind,
            bytes,
            data_shards: k,
            parity_shards: m,
            encode_mib_s: mib_per_second(bytes, &encode_times),
            reconstruct_mib_s: mib_per_second(bytes, &reconstruct_times),
            encode_p50_ms: percentile(&encode_times, 0.50),
            encode_p95_ms: percentile(&encode_times, 0.95),
            reconstruct_p50_ms: percentile(&reconstruct_times, 0.50),
            reconstruct_p95_ms: percentile(&reconstruct_times, 0.95),
        },
        backend,
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    anyhow::ensure!(
        args.iterations > 0,
        "--iterations must be greater than zero"
    );

    let sizes = args
        .sizes
        .split(',')
        .map(parse_size)
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(!sizes.is_empty(), "at least one benchmark size is required");

    let backend_kind: BackendKind = args.backend.into();
    let mut samples = Vec::new();
    let mut last_backend = None;

    println!(
        "{:<14} {:>10} {:>8} {:>14} {:>14} {:>12} {:>12}",
        "scheme", "size", "layout", "encode MiB/s", "rebuild MiB/s", "enc p95 ms", "rec p95 ms"
    );

    for scheme in schemes(args.scheme) {
        let (k, m) = default_geometry(scheme, args.data_shards, args.parity_shards);
        for &bytes in &sizes {
            let (sample, backend) = bench_one(
                backend_kind,
                scheme,
                bytes,
                k,
                m,
                BenchRun {
                    iterations: args.iterations,
                    gpu_threshold_bytes: args.gpu_threshold_bytes,
                    seed: args.seed,
                },
            )
            .await
            .with_context(|| format!("benchmark {:?} {bytes} bytes {k}+{m}", scheme))?;

            if args.require_acceleration {
                let status = backend.acceleration_status();
                let metrics = backend.metrics_snapshot();
                anyhow::ensure!(
                    status.selected_gpu.is_some(),
                    "requested acceleration is unavailable for {:?}",
                    backend_kind
                );
                if backend_kind != BackendKind::Auto {
                    anyhow::ensure!(
                        status.selected_gpu == Some(backend_kind),
                        "requested {:?} but selected {:?}",
                        backend_kind,
                        status.selected_gpu
                    );
                }
                anyhow::ensure!(
                    metrics.gpu_bytes > 0,
                    "accelerator was selected but no GPU bytes were executed"
                );
                anyhow::ensure!(
                    metrics.gpu_fallbacks == 0,
                    "accelerator execution fell back {} time(s)",
                    metrics.gpu_fallbacks
                );
            }

            println!(
                "{:<14?} {:>10} {:>3}+{:<4} {:>14.1} {:>14.1} {:>12.3} {:>12.3}",
                sample.scheme,
                sample.bytes,
                sample.data_shards,
                sample.parity_shards,
                sample.encode_mib_s,
                sample.reconstruct_mib_s,
                sample.encode_p95_ms,
                sample.reconstruct_p95_ms
            );
            samples.push(sample);
            last_backend = Some(backend);
        }
    }

    let backend = last_backend.context("no benchmark samples ran")?;
    let acceleration = serde_json::to_value(backend.acceleration_status())?;
    let metrics = serde_json::to_value(backend.metrics_snapshot())?;
    let report = Report {
        product: "Kagi",
        version: env!("CARGO_PKG_VERSION"),
        environment: Environment {
            unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            cpu_threads: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            rust_version: rust_version(),
        },
        acceleration,
        metrics,
        samples,
    };

    if let Some(path) = args.json {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes_are_stable() {
        assert_eq!(parse_size("1MiB").unwrap(), 1_048_576);
        assert_eq!(parse_size("8M").unwrap(), 8_000_000);
        assert!(parse_size("3watts").is_err());
    }

    #[test]
    fn msr_default_geometry_is_valid() {
        let (k, m) = default_geometry(ErasureScheme::Msr, None, None);
        ErasureLayout {
            scheme: ErasureScheme::Msr,
            data_shards: k,
            parity_shards: m,
            repair_helpers: None,
        }
        .validate()
        .unwrap();
    }
}
