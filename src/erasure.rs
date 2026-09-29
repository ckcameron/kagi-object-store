// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi erasure-coding and exact-repair backends.
//!
//! The runtime exposes Reed-Solomon, product-matrix MSR, and CLAY through one validated
//! layout abstraction. CPU implementations are always available; CUDA can accelerate bulk
//! matrix work when the crate is built with the `cuda` feature. Backend selection remains
//! explicit so a GPU failure can fall back without changing the object format on disk.

// CPU/CUDA erasure-coding backends and adaptive dispatch.
//! Runtime erasure coding for Reed-Solomon, product-matrix MSR, and CLAY.
//! CLAY's CPU reference implementation is provided by the Apache-2.0 `clay-codes`
//! dependency; CUDA acceleration in this file is Kagi-specific.
#[path = "cpu_isa.rs"]
mod cpu_isa;
#[cfg(all(unix, any(feature = "isa-l", feature = "ipp", feature = "aocl")))]
#[path = "cpu_libraries.rs"]
mod cpu_libraries;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clay_codes::ClayCode;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
};
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
/// Supported BackendKind states or operations.
/// Requested execution backend for erasure operations.
pub enum BackendKind {
    /// Select the best initialized accelerator and fall back to CPU.
    #[default]
    Auto,
    /// Force the CPU implementation.
    Cpu,
    /// Request NVIDIA CUDA; requires the cuda Cargo feature and runtime support.
    Cuda,
    /// Request AMD HIP/ROCm; requires the hip/rocm Cargo feature and runtime support.
    Hip,
    /// Request OpenCL; requires the opencl Cargo feature and runtime support.
    Opencl,
}
/// Codec family used by a particular immutable object version.
///
/// `Default` intentionally remains Reed-Solomon for backwards compatibility
/// when deserializing manifests created before the codec-family field existed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ErasureScheme {
    #[default]
    ReedSolomon,
    Msr,
    Clay,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Runtime erasure-coding and accelerator policy for newly protected objects.
pub struct ErasureConfig {
    /// Requested execution backend. Default: auto.
    #[serde(default)]
    pub backend: BackendKind,
    /// Codec for new objects. Runtime default: CLAY.
    #[serde(default = "default_runtime_scheme")]
    pub scheme: ErasureScheme,
    /// Number of data shards (k). Default: 6.
    #[serde(default = "default_k")]
    pub data_shards: usize,
    /// Number of parity shards (m). Default: 3.
    #[serde(default = "default_m")]
    pub parity_shards: usize,
    /// Helper count for exact repair.  CLAY accepts k+1..n-1.  Product-matrix
    /// MSR currently implements the canonical d=2k-2 construction.
    #[serde(default)]
    pub repair_helpers: Option<usize>,
    /// Minimum payload size for attempting GPU dispatch. Default: 1 MiB.
    #[serde(default = "default_gpu_threshold")]
    pub gpu_threshold_bytes: usize,
    /// Maximum number of GPU operations admitted concurrently. Default: 32.
    #[serde(default = "default_gpu_queue")]
    pub max_gpu_inflight: u64,
    /// Maximum cached linear transform size.  Prevents an unexpectedly large
    /// CLAY sub-packetization level from consuming unbounded memory.
    #[serde(default = "default_matrix_cache_bytes")]
    pub max_matrix_cache_bytes: usize,
}
/// Implements the default runtime scheme step and keeps its validation and state transitions visible at the call site.
fn default_runtime_scheme() -> ErasureScheme {
    ErasureScheme::Clay
}
/// Implements the default k step and keeps its validation and state transitions visible at the call site.
fn default_k() -> usize {
    6
}
/// Implements the default m step and keeps its validation and state transitions visible at the call site.
fn default_m() -> usize {
    3
}
/// Implements the default gpu threshold step and keeps its validation and state transitions visible at the call site.
fn default_gpu_threshold() -> usize {
    1 << 20
}
/// Implements the default gpu queue step and keeps its validation and state transitions visible at the call site.
fn default_gpu_queue() -> u64 {
    32
}
/// Implements the default matrix cache bytes step and keeps its validation and state transitions visible at the call site.
fn default_matrix_cache_bytes() -> usize {
    256 << 20
}
impl Default for ErasureConfig {
    fn default() -> Self {
        Self {
            backend: BackendKind::Auto,
            scheme: default_runtime_scheme(),
            data_shards: default_k(),
            parity_shards: default_m(),
            repair_helpers: None,
            gpu_threshold_bytes: default_gpu_threshold(),
            max_gpu_inflight: default_gpu_queue(),
            max_matrix_cache_bytes: default_matrix_cache_bytes(),
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
/// Kagi state or configuration used by the ErasureLayout path.
pub struct ErasureLayout {
    pub scheme: ErasureScheme,
    pub data_shards: usize,
    pub parity_shards: usize,
    #[serde(default)]
    pub repair_helpers: Option<usize>,
}
impl ErasureLayout {
    pub fn n(&self) -> usize {
        self.data_shards + self.parity_shards
    }
    pub fn validate(&self) -> Result<()> {
        validate_common(self.data_shards, self.parity_shards)?;
        match self.scheme {
            ErasureScheme::ReedSolomon => Ok(()),
            ErasureScheme::Clay => {
                let d = clay_d(self.data_shards, self.parity_shards, self.repair_helpers)?;
                if d < self.data_shards + 1 || d >= self.n() {
                    bail!("CLAY requires k+1 <= d <= k+m-1")
                }
                Ok(())
            }
            ErasureScheme::Msr => {
                let want = 2 * self.data_shards - 2;
                let d = self.repair_helpers.unwrap_or(want);
                if d != want {
                    bail!("product-matrix MSR currently requires d=2k-2 ({want}), got {d}")
                }
                if self.n() <= d {
                    bail!(
                        "product-matrix MSR requires n >= d+1; k={} m={} gives n={} d={}",
                        self.data_shards,
                        self.parity_shards,
                        self.n(),
                        d
                    )
                }
                Ok(())
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the EncodedShards path.
pub struct EncodedShards {
    pub original_len: u64,
    pub data_shards: u16,
    pub parity_shards: u16,
    #[serde(default)]
    pub scheme: ErasureScheme,
    #[serde(default)]
    pub repair_helpers: Option<u16>,
    #[serde(default)]
    pub sub_chunk_no: u32,
    pub shards: Vec<Vec<u8>>,
}
/// Data that one helper must return for bandwidth-optimal exact repair.
///
/// `SubChunks` is used by CLAY and causes the fragment server to read only the
/// requested sub-packets. `Projection` is used by product-matrix MSR and asks
/// the helper to return a GF(256) linear projection of the rows it stores.
#[derive(Debug, Clone)]
pub enum RepairFetch {
    SubChunks {
        shard: usize,
        alpha: usize,
        indices: Vec<usize>,
    },
    Projection {
        shard: usize,
        rows: usize,
        coeff: Vec<u8>,
    },
}
impl RepairFetch {
    pub fn shard(&self) -> usize {
        match self {
            Self::SubChunks { shard, .. } | Self::Projection { shard, .. } => *shard,
        }
    }
    pub fn output_rows(&self) -> usize {
        match self {
            Self::SubChunks { indices, .. } => indices.len(),
            Self::Projection { coeff, rows, .. } => coeff.len() / rows,
        }
    }
}
/// Codec-produced plan for exact single-shard repair. The cluster data plane
/// executes `fetches` on helper nodes, concatenates the returned rows in plan
/// order, then applies `recovery_coeff` to reconstruct the lost full chunk.
#[derive(Debug, Clone)]
pub struct ExactRepairPlan {
    pub chunk_len: usize,
    pub row_len: usize,
    pub fetches: Vec<RepairFetch>,
    pub input_rows: usize,
    pub output_rows: usize,
    pub recovery_coeff: Vec<u8>,
}
#[async_trait]
pub trait ErasureBackend: Send + Sync {
    fn default_layout(&self, k: usize, m: usize) -> Result<ErasureLayout>;
    async fn encode_layout(&self, data: &[u8], layout: &ErasureLayout) -> Result<EncodedShards>;
    async fn reconstruct_layout(
        &self,
        shards: &mut [Option<Vec<u8>>],
        original_len: u64,
        layout: &ErasureLayout,
    ) -> Result<Vec<u8>>;
    #[cfg(test)]
    async fn repair_shard_layout(
        &self,
        shards: &[Option<Vec<u8>>],
        lost: usize,
        layout: &ErasureLayout,
    ) -> Result<Vec<u8>>;
    /// Return a bandwidth-optimal repair plan when the selected codec supports
    /// exact single-node repair. Reed-Solomon returns `None`.
    fn exact_repair_plan(
        &self,
        _available: &[usize],
        _lost: usize,
        _chunk_len: usize,
        _layout: &ErasureLayout,
    ) -> Result<Option<ExactRepairPlan>> {
        Ok(None)
    }
    /// Apply an arbitrary GF(256) linear transform. AdaptiveBackend overrides
    /// this to use CUDA above the configured threshold; CPU is the reference.
    async fn linear_transform(
        &self,
        input: &[u8],
        in_rows: usize,
        coeff: &[u8],
        out_rows: usize,
        row_len: usize,
    ) -> Result<Vec<u8>> {
        gf_matrix_apply_cpu(input, in_rows, coeff, out_rows, row_len)
    }
    /// Finish an exact-repair plan from helper payloads. Each payload contains
    /// the rows requested by the corresponding `RepairFetch`.
    async fn apply_exact_repair(
        &self,
        plan: &ExactRepairPlan,
        helper_payloads: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        if helper_payloads.len() != plan.fetches.len() {
            bail!(
                "exact repair expected {} helper payloads, got {}",
                plan.fetches.len(),
                helper_payloads.len()
            )
        }
        let mut input = Vec::with_capacity(plan.input_rows * plan.row_len);
        let mut rows = 0usize;
        for (fetch, payload) in plan.fetches.iter().zip(helper_payloads) {
            let want_rows = fetch.output_rows();
            if payload.len() != want_rows * plan.row_len {
                bail!(
                    "helper {} returned {} bytes, expected {}",
                    fetch.shard(),
                    payload.len(),
                    want_rows * plan.row_len
                )
            }
            rows += want_rows;
            input.extend_from_slice(payload);
        }
        if rows != plan.input_rows {
            bail!(
                "exact repair helper-row mismatch: plan={} actual={rows}",
                plan.input_rows
            )
        }
        let out = self
            .linear_transform(
                &input,
                plan.input_rows,
                &plan.recovery_coeff,
                plan.output_rows,
                plan.row_len,
            )
            .await?;
        if out.len() != plan.chunk_len {
            bail!(
                "exact repair produced {} bytes, expected {}",
                out.len(),
                plan.chunk_len
            )
        }
        Ok(out)
    }
    async fn encode(&self, data: &[u8], k: usize, m: usize) -> Result<EncodedShards> {
        let layout = self.default_layout(k, m)?;
        self.encode_layout(data, &layout).await
    }
}
/// Implements the validate common step and keeps its validation and state transitions visible at the call site.
fn validate_common(k: usize, m: usize) -> Result<()> {
    if k == 0 || m == 0 || k + m > 255 {
        bail!("invalid GF(2^8) layout k={k} m={m}; require 1 <= k,m and n <= 255")
    }
    Ok(())
}
/// Implements the clay d step and keeps its validation and state transitions visible at the call site.
fn clay_d(k: usize, m: usize, d: Option<usize>) -> Result<usize> {
    if m < 2 {
        bail!("CLAY requires at least two parity nodes so d can be >= k+1")
    }
    Ok(d.unwrap_or(k + m - 1))
}
// -----------------------------------------------------------------------------
// GF(2^8) helpers.  Polynomial 0x11d, matching the existing CUDA and RS paths.
// -----------------------------------------------------------------------------
#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80 != 0;
        a <<= 1;
        if hi {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    r
}
/// Implements the gf pow step and keeps its validation and state transitions visible at the call site.
fn gf_pow(mut a: u8, mut e: usize) -> u8 {
    let mut r = 1u8;
    while e > 0 {
        if e & 1 != 0 {
            r = gf_mul(r, a);
        }
        e >>= 1;
        if e != 0 {
            a = gf_mul(a, a);
        }
    }
    r
}
/// Implements the gf inv step and keeps its validation and state transitions visible at the call site.
fn gf_inv(a: u8) -> Result<u8> {
    if a == 0 {
        bail!("GF inverse of zero")
    } else {
        Ok(gf_pow(a, 254))
    }
}
/// Invert an n×n row-major matrix over GF(2^8).
fn gf_matrix_inverse(a: &[u8], n: usize) -> Result<Vec<u8>> {
    if a.len() != n * n {
        bail!("matrix length mismatch")
    }
    let mut aug = vec![0u8; n * (2 * n)];
    for r in 0..n {
        aug[r * 2 * n..r * 2 * n + n].copy_from_slice(&a[r * n..(r + 1) * n]);
        aug[r * 2 * n + n + r] = 1;
    }
    for col in 0..n {
        let pivot = (col..n)
            .find(|&r| aug[r * 2 * n + col] != 0)
            .context("singular GF matrix")?;
        if pivot != col {
            for c in 0..2 * n {
                aug.swap(col * 2 * n + c, pivot * 2 * n + c);
            }
        }
        let inv = gf_inv(aug[col * 2 * n + col])?;
        for c in 0..2 * n {
            aug[col * 2 * n + c] = gf_mul(aug[col * 2 * n + c], inv);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = aug[r * 2 * n + col];
            if f == 0 {
                continue;
            }
            for c in 0..2 * n {
                aug[r * 2 * n + c] ^= gf_mul(f, aug[col * 2 * n + c]);
            }
        }
    }
    let mut out = vec![0u8; n * n];
    for r in 0..n {
        out[r * n..(r + 1) * n].copy_from_slice(&aug[r * 2 * n + n..(r + 1) * 2 * n]);
    }
    Ok(out)
}
/// Apply a row-major GF matrix to equally-sized byte rows.
fn gf_matrix_apply_cpu(
    inputs: &[u8],
    in_rows: usize,
    coeff: &[u8],
    out_rows: usize,
    row_len: usize,
) -> Result<Vec<u8>> {
    if Some(inputs.len()) != in_rows.checked_mul(row_len)
        || Some(coeff.len()) != out_rows.checked_mul(in_rows)
    {
        bail!("GF matrix apply shape mismatch")
    }
    #[cfg(all(unix, feature = "isa-l"))]
    if row_len >= 4096 {
        if let Some(result) = cpu_libraries::matrix(inputs, in_rows, coeff, out_rows, row_len) {
            return Ok(result);
        }
    }
    let mut out = vec![
        0u8;
        out_rows
            .checked_mul(row_len)
            .context("GF output size overflow")?
    ];
    for o in 0..out_rows {
        for i in 0..in_rows {
            let c = coeff[o * in_rows + i];
            if c == 0 {
                continue;
            }
            let src = &inputs[i * row_len..(i + 1) * row_len];
            let dst = &mut out[o * row_len..(o + 1) * row_len];
            if c == 1 {
                #[cfg(all(unix, feature = "ipp"))]
                if row_len >= 4096 && cpu_libraries::xor(dst, src) {
                    continue;
                }
                for (d, s) in dst.iter_mut().zip(src) {
                    *d ^= *s;
                }
            } else {
                cpu_isa::multiply_add(dst, src, c);
            }
        }
    }
    Ok(out)
}
/// Implements the pack source rows step and keeps its validation and state transitions visible at the call site.
fn pack_source_rows(data: &[u8], rows: usize, row_len: usize) -> Vec<u8> {
    let mut packed = vec![0u8; rows * row_len];
    let copy_len = data.len().min(packed.len());
    #[cfg(all(unix, feature = "aocl"))]
    if copy_len >= 1024 * 1024 && cpu_libraries::copy(&mut packed[..copy_len], &data[..copy_len]) {
        return packed;
    }
    packed[..copy_len].copy_from_slice(&data[..copy_len]);
    packed
}
/// Implements the rows to node chunks step and keeps its validation and state transitions visible at the call site.
fn rows_to_node_chunks(rows: &[u8], n: usize, alpha: usize, row_len: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|node| {
            let start = node * alpha * row_len;
            rows[start..start + alpha * row_len].to_vec()
        })
        .collect()
}
/// Implements the node chunks to rows step and keeps its validation and state transitions visible at the call site.
fn node_chunks_to_rows(chunks: &[(usize, &[u8])], alpha: usize, row_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(chunks.len() * alpha * row_len);
    for (_, chunk) in chunks {
        if chunk.len() != alpha * row_len {
            bail!("node chunk length is not alpha * row_len")
        }
        out.extend_from_slice(chunk);
    }
    Ok(out)
}
// -----------------------------------------------------------------------------
// Reed-Solomon reference backend.
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct CpuBackend;
#[async_trait]
impl ErasureBackend for CpuBackend {
    fn default_layout(&self, k: usize, m: usize) -> Result<ErasureLayout> {
        let l = ErasureLayout {
            scheme: ErasureScheme::ReedSolomon,
            data_shards: k,
            parity_shards: m,
            repair_helpers: None,
        };
        l.validate()?;
        Ok(l)
    }
    async fn encode_layout(&self, data: &[u8], layout: &ErasureLayout) -> Result<EncodedShards> {
        if layout.scheme != ErasureScheme::ReedSolomon {
            bail!("CpuBackend only implements Reed-Solomon")
        }
        let (k, m) = (layout.data_shards, layout.parity_shards);
        validate_common(k, m)?;
        let rs = ReedSolomon::new(k, m)?;
        let shard_len = data.len().div_ceil(k).max(1);
        let mut shards = vec![vec![0u8; shard_len]; k + m];
        for (i, chunk) in data.chunks(shard_len).enumerate() {
            shards[i][..chunk.len()].copy_from_slice(chunk);
        }
        rs.encode(&mut shards)?;
        Ok(EncodedShards {
            original_len: data.len() as u64,
            data_shards: k as u16,
            parity_shards: m as u16,
            scheme: ErasureScheme::ReedSolomon,
            repair_helpers: None,
            sub_chunk_no: 1,
            shards,
        })
    }
    async fn reconstruct_layout(
        &self,
        shards: &mut [Option<Vec<u8>>],
        original_len: u64,
        layout: &ErasureLayout,
    ) -> Result<Vec<u8>> {
        if layout.scheme != ErasureScheme::ReedSolomon {
            bail!("CpuBackend only implements Reed-Solomon")
        }
        let (k, m) = (layout.data_shards, layout.parity_shards);
        validate_common(k, m)?;
        if shards.len() != k + m {
            bail!("expected {} shards, got {}", k + m, shards.len())
        }
        ReedSolomon::new(k, m)?.reconstruct(shards)?;
        let mut out = Vec::with_capacity(original_len as usize);
        for s in shards.iter().take(k) {
            out.extend_from_slice(
                s.as_ref()
                    .context("data shard missing after reconstruction")?,
            );
        }
        out.truncate(original_len as usize);
        Ok(out)
    }
    #[cfg(test)]
    async fn repair_shard_layout(
        &self,
        shards: &[Option<Vec<u8>>],
        lost: usize,
        layout: &ErasureLayout,
    ) -> Result<Vec<u8>> {
        let mut owned = shards.to_vec();
        if lost >= owned.len() {
            bail!("lost shard out of range")
        }
        owned[lost] = None;
        ReedSolomon::new(layout.data_shards, layout.parity_shards)?.reconstruct(&mut owned)?;
        owned[lost]
            .take()
            .context("RS repair did not reconstruct shard")
    }
}
// -----------------------------------------------------------------------------
// Product-matrix exact-repair MSR (Rashmi-Shah-Kumar construction, d=2k-2).
// -----------------------------------------------------------------------------
#[derive(Clone)]
struct PmLayout {
    k: usize,
    m: usize,
    n: usize,
    alpha: usize,
    d: usize,
    b: usize,
    phi: Vec<u8>,
    lambda: Vec<u8>,
    psi: Vec<u8>,
    generator: Vec<u8>,
}
/// Named type used to keep the PmCache data flow readable.
type PmCache = Mutex<HashMap<(usize, usize), Arc<PmLayout>>>;
static PM_CACHE: OnceLock<PmCache> = OnceLock::new();
/// Implements the pm layout step and keeps its validation and state transitions visible at the call site.
fn pm_layout(k: usize, m: usize) -> Result<Arc<PmLayout>> {
    let cache = PM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&(k, m)).cloned() {
        return Ok(v);
    }
    validate_common(k, m)?;
    if k < 2 {
        bail!("product-matrix MSR requires k>=2")
    }
    let alpha = k - 1;
    let d = 2 * alpha;
    let n = k + m;
    let b = k * alpha;
    if n <= d {
        bail!("product-matrix MSR requires n>=2k-1; k={k} m={m}")
    }
    // Pick distinct evaluation points whose alpha-th powers are also distinct.
    let mut xs = Vec::with_capacity(n);
    let mut lambdas = BTreeSet::new();
    for x in 1u16..=255 {
        let xx = x as u8;
        let lam = gf_pow(xx, alpha);
        if lambdas.insert(lam) {
            xs.push(xx);
            if xs.len() == n {
                break;
            }
        }
    }
    if xs.len() != n {
        bail!("GF(256) cannot supply {n} distinct product-matrix evaluation/lambda pairs for alpha={alpha}")
    }
    let mut phi = vec![0u8; n * alpha];
    let mut lambda = vec![0u8; n];
    let mut psi = vec![0u8; n * d];
    for i in 0..n {
        lambda[i] = gf_pow(xs[i], alpha);
        for j in 0..alpha {
            phi[i * alpha + j] = gf_pow(xs[i], j);
        }
        for j in 0..alpha {
            psi[i * d + j] = phi[i * alpha + j];
            psi[i * d + alpha + j] = gf_mul(lambda[i], phi[i * alpha + j]);
        }
    }
    // Build the systematic source-symbol -> stored-symbol generator by applying
    // the two symmetric message matrices to every basis source symbol.
    let tri = alpha * (alpha + 1) / 2;
    debug_assert_eq!(2 * tri, b);
    let mut pairs = Vec::with_capacity(tri);
    for r in 0..alpha {
        for c in r..alpha {
            pairs.push((r, c));
        }
    }
    let out_rows = n * alpha;
    let mut generator = vec![0u8; out_rows * b];
    for src in 0..b {
        let is_s2 = src >= tri;
        let (r, c) = pairs[src % tri];
        for node in 0..n {
            let scale = if is_s2 { lambda[node] } else { 1 };
            for col in 0..alpha {
                let mut v = 0u8;
                if c == col {
                    v ^= phi[node * alpha + r];
                }
                if r == col && r != c {
                    v ^= phi[node * alpha + c];
                }
                generator[(node * alpha + col) * b + src] = gf_mul(scale, v);
            }
        }
    }
    let out = Arc::new(PmLayout {
        k,
        m,
        n,
        alpha,
        d,
        b,
        phi,
        lambda,
        psi,
        generator,
    });
    cache.lock().unwrap().insert((k, m), out.clone());
    Ok(out)
}
/// Implements the pm encode with step and keeps its validation and state transitions visible at the call site.
fn pm_encode_with<F>(data: &[u8], p: &PmLayout, apply: F) -> Result<EncodedShards>
where
    F: Fn(&[u8], usize, &[u8], usize, usize) -> Result<Vec<u8>>,
{
    let row_len = data.len().div_ceil(p.b).max(1);
    let input = pack_source_rows(data, p.b, row_len);
    let rows = apply(&input, p.b, &p.generator, p.n * p.alpha, row_len)?;
    Ok(EncodedShards {
        original_len: data.len() as u64,
        data_shards: p.k as u16,
        parity_shards: p.m as u16,
        scheme: ErasureScheme::Msr,
        repair_helpers: Some(p.d as u16),
        sub_chunk_no: p.alpha as u32,
        shards: rows_to_node_chunks(&rows, p.n, p.alpha, row_len),
    })
}
/// Implements the pm reconstruct with step and keeps its validation and state transitions visible at the call site.
fn pm_reconstruct_with<F>(
    shards: &[Option<Vec<u8>>],
    original_len: u64,
    p: &PmLayout,
    apply: F,
) -> Result<Vec<u8>>
where
    F: Fn(&[u8], usize, &[u8], usize, usize) -> Result<Vec<u8>>,
{
    if shards.len() != p.n {
        bail!("expected {} PM-MSR shards", p.n)
    }
    let chosen: Vec<(usize, &[u8])> = shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_deref().map(|x| (i, x)))
        .take(p.k)
        .collect();
    if chosen.len() < p.k {
        bail!("need at least k={} PM-MSR nodes", p.k)
    }
    let chunk_len = chosen[0].1.len();
    if !chunk_len.is_multiple_of(p.alpha) {
        bail!("PM-MSR chunk is not divisible by alpha")
    }
    if chosen.iter().any(|(_, s)| s.len() != chunk_len) {
        bail!("inconsistent PM-MSR chunk lengths")
    }
    let row_len = chunk_len / p.alpha;
    let observed = node_chunks_to_rows(&chosen, p.alpha, row_len)?;
    let mut a = Vec::with_capacity(p.b * p.b);
    for (node, _) in &chosen {
        for sym in 0..p.alpha {
            let gr = (node * p.alpha + sym) * p.b;
            a.extend_from_slice(&p.generator[gr..gr + p.b]);
        }
    }
    let inv = gf_matrix_inverse(&a, p.b)?;
    let source = apply(&observed, p.b, &inv, p.b, row_len)?;
    let mut out = source;
    out.truncate(original_len as usize);
    Ok(out)
}
#[cfg(test)]
/// Implements the pm repair matrix step and keeps its validation and state transitions visible at the call site.
fn pm_repair_matrix(p: &PmLayout, lost: usize, helpers: &[usize]) -> Result<Vec<u8>> {
    if lost >= p.n || helpers.len() != p.d || helpers.contains(&lost) {
        bail!("invalid PM-MSR repair helper set")
    }
    let mut psi_h = Vec::with_capacity(p.d * p.d);
    for &h in helpers {
        psi_h.extend_from_slice(&p.psi[h * p.d..(h + 1) * p.d]);
    }
    let inv = gf_matrix_inverse(&psi_h, p.d)?;
    // First map helper projections -> lost alpha symbols, then expand each
    // helper projection into the dot product with phi_lost across its alpha rows.
    let mut r = vec![0u8; p.alpha * (p.d * p.alpha)];
    for out in 0..p.alpha {
        for hpos in 0..p.d {
            let a =
                inv[out * p.d + hpos] ^ gf_mul(p.lambda[lost], inv[(p.alpha + out) * p.d + hpos]);
            for s in 0..p.alpha {
                r[out * (p.d * p.alpha) + hpos * p.alpha + s] =
                    gf_mul(a, p.phi[lost * p.alpha + s]);
            }
        }
    }
    Ok(r)
}
#[cfg(test)]
/// Implements the pm repair with step and keeps its validation and state transitions visible at the call site.
fn pm_repair_with<F>(
    shards: &[Option<Vec<u8>>],
    lost: usize,
    p: &PmLayout,
    apply: F,
) -> Result<Vec<u8>>
where
    F: Fn(&[u8], usize, &[u8], usize, usize) -> Result<Vec<u8>>,
{
    if shards.len() != p.n {
        bail!("PM-MSR shard vector length mismatch")
    }
    let helpers: Vec<usize> = shards
        .iter()
        .enumerate()
        .filter(|(i, s)| *i != lost && s.is_some())
        .map(|(i, _)| i)
        .take(p.d)
        .collect();
    if helpers.len() != p.d {
        bail!("PM-MSR exact repair needs d={} helpers", p.d)
    }
    let chunk_len = shards[helpers[0]].as_ref().unwrap().len();
    if !chunk_len.is_multiple_of(p.alpha) {
        bail!("invalid PM-MSR chunk length")
    }
    let row_len = chunk_len / p.alpha;
    let borrowed: Vec<(usize, &[u8])> = helpers
        .iter()
        .map(|&h| (h, shards[h].as_deref().unwrap()))
        .collect();
    let input = node_chunks_to_rows(&borrowed, p.alpha, row_len)?;
    let coeff = pm_repair_matrix(p, lost, &helpers)?;
    apply(&input, p.d * p.alpha, &coeff, p.alpha, row_len)
}
/// Build a bandwidth-optimal product-matrix MSR repair plan. Each helper
/// returns one beta=1 projection instead of its full alpha-row shard.
fn pm_exact_repair_plan(
    p: &PmLayout,
    lost: usize,
    available: &[usize],
    chunk_len: usize,
) -> Result<ExactRepairPlan> {
    if lost >= p.n {
        bail!("PM-MSR lost shard out of range")
    }
    if chunk_len == 0 || !chunk_len.is_multiple_of(p.alpha) {
        bail!("invalid PM-MSR chunk length {chunk_len}")
    }
    let helpers: Vec<usize> = available
        .iter()
        .copied()
        .filter(|&h| h != lost && h < p.n)
        .take(p.d)
        .collect();
    if helpers.len() != p.d {
        bail!("PM-MSR exact repair needs d={} available helpers", p.d)
    }
    let mut psi_h = Vec::with_capacity(p.d * p.d);
    for &h in &helpers {
        psi_h.extend_from_slice(&p.psi[h * p.d..(h + 1) * p.d]);
    }
    let inv = gf_matrix_inverse(&psi_h, p.d)?;
    let mut recovery = vec![0u8; p.alpha * p.d];
    for out in 0..p.alpha {
        for hpos in 0..p.d {
            recovery[out * p.d + hpos] =
                inv[out * p.d + hpos] ^ gf_mul(p.lambda[lost], inv[(p.alpha + out) * p.d + hpos]);
        }
    }
    let phi_lost = p.phi[lost * p.alpha..(lost + 1) * p.alpha].to_vec();
    let fetches = helpers
        .into_iter()
        .map(|shard| RepairFetch::Projection {
            shard,
            rows: p.alpha,
            coeff: phi_lost.clone(),
        })
        .collect();
    Ok(ExactRepairPlan {
        chunk_len,
        row_len: chunk_len / p.alpha,
        fetches,
        input_rows: p.d,
        output_rows: p.alpha,
        recovery_coeff: recovery,
    })
}
// -----------------------------------------------------------------------------
// CLAY.  CPU correctness comes from `clay-codes`; Kagi derives equivalent
// linear transforms once per geometry so encode and exact repair can execute on
// CUDA without changing the on-disk CLAY wire layout.
// -----------------------------------------------------------------------------
#[cfg_attr(
    not(any(feature = "cuda", feature = "hip", feature = "opencl")),
    allow(dead_code)
)]
#[derive(Clone)]
struct ClayGenerator {
    alpha: usize,
    matrix: Arc<Vec<u8>>,
}
/// Named type used to keep the ClayGeneratorCache data flow readable.
type ClayGeneratorCache = Mutex<HashMap<(usize, usize, usize), ClayGenerator>>;
static CLAY_GEN_CACHE: OnceLock<ClayGeneratorCache> = OnceLock::new();
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl", test))]
/// Named type used to keep the ClayDecodeCache data flow readable.
type ClayDecodeCache = Mutex<HashMap<(usize, usize, usize, Vec<usize>), Arc<Vec<u8>>>>;
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl", test))]
static CLAY_DECODE_CACHE: OnceLock<ClayDecodeCache> = OnceLock::new();
/// Named type used to keep the ClayRepairCache data flow readable.
type ClayRepairCache = Mutex<HashMap<(usize, usize, usize, usize, Vec<usize>), Arc<Vec<u8>>>>;
static CLAY_REPAIR_CACHE: OnceLock<ClayRepairCache> = OnceLock::new();
/// Implements the clay code step and keeps its validation and state transitions visible at the call site.
fn clay_code(layout: &ErasureLayout) -> Result<ClayCode> {
    let d = clay_d(
        layout.data_shards,
        layout.parity_shards,
        layout.repair_helpers,
    )?;
    ClayCode::new(layout.data_shards, layout.parity_shards, d)
        .map_err(|e| anyhow!("CLAY init failed: {e:?}"))
}
/// Implements the clay generator step and keeps its validation and state transitions visible at the call site.
fn clay_generator(layout: &ErasureLayout, max_bytes: usize) -> Result<ClayGenerator> {
    let d = clay_d(
        layout.data_shards,
        layout.parity_shards,
        layout.repair_helpers,
    )?;
    let key = (layout.data_shards, layout.parity_shards, d);
    let cache = CLAY_GEN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&key).cloned() {
        return Ok(v);
    }
    let clay = clay_code(layout)?;
    let alpha = clay.sub_chunk_no;
    let in_rows = layout.data_shards * alpha;
    let out_rows = layout.n() * alpha;
    let bytes = in_rows
        .checked_mul(out_rows)
        .context("CLAY generator size overflow")?;
    if bytes > max_bytes {
        bail!("CLAY CUDA generator would require {bytes} bytes, over max_matrix_cache_bytes={max_bytes}")
    }
    let mut matrix = vec![0u8; bytes];
    // `clay-codes` uses a 2-byte minimum subchunk.  Exciting byte zero in one
    // source subchunk and observing byte zero in every encoded subchunk yields
    // one column of the GF(256) generator because the codec is byte-column linear.
    let basis_len = in_rows * 2;
    for col in 0..in_rows {
        let mut basis = vec![0u8; basis_len];
        basis[col * 2] = 1;
        let chunks = clay.encode(&basis);
        for node in 0..layout.n() {
            for sc in 0..alpha {
                matrix[(node * alpha + sc) * in_rows + col] = chunks[node][sc * 2];
            }
        }
    }
    // Guard the CUDA/linearized path against a finite-field representation
    // mismatch with the reference crate.  The generator above is sampled from
    // `clay-codes`; this deterministic probe verifies that Kagi's GF(256)
    // multiply applies that sampled matrix identically before it is cached.
    // If a future upstream implementation changes its byte-field basis, the
    // accelerated path fails closed and AdaptiveBackend falls back to the
    // reference CPU codec rather than producing incompatible fragments.
    let probe_row_len = 4usize;
    let mut probe = vec![0u8; in_rows * probe_row_len];
    for (i, b) in probe.iter_mut().enumerate() {
        *b = ((i * 73 + 19) & 0xff) as u8;
    }
    let reference_input = probe.clone();
    let reference_chunks = clay.encode(&reference_input);
    let reference_rows: Vec<u8> = reference_chunks.into_iter().flatten().collect();
    let linear_rows = gf_matrix_apply_cpu(&probe, in_rows, &matrix, out_rows, probe_row_len)?;
    if linear_rows != reference_rows {
        bail!("CLAY byte-field basis is incompatible with Kagi GF(256) acceleration; refusing to cache linear transform");
    }
    let out = ClayGenerator {
        alpha,
        matrix: Arc::new(matrix),
    };
    cache.lock().unwrap().insert(key, out.clone());
    Ok(out)
}
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl", test))]
/// Implements the clay encode linearized with step and keeps its validation and state transitions visible at the call site.
fn clay_encode_linearized_with<F>(
    data: &[u8],
    layout: &ErasureLayout,
    max_bytes: usize,
    apply: F,
) -> Result<EncodedShards>
where
    F: Fn(&[u8], usize, &[u8], usize, usize) -> Result<Vec<u8>>,
{
    let g = clay_generator(layout, max_bytes)?;
    let k = layout.data_shards;
    let n = layout.n();
    let alpha = g.alpha;
    let min_size = k * alpha * 2;
    let padded_len = if data.is_empty() {
        min_size
    } else {
        (data.len().div_ceil(min_size) * min_size).max(min_size)
    };
    let chunk_size = padded_len / k;
    let row_len = chunk_size / alpha;
    let in_rows = k * alpha;
    let input = pack_source_rows(data, in_rows, row_len);
    let rows = apply(&input, in_rows, g.matrix.as_slice(), n * alpha, row_len)?;
    Ok(EncodedShards {
        original_len: data.len() as u64,
        data_shards: k as u16,
        parity_shards: layout.parity_shards as u16,
        scheme: ErasureScheme::Clay,
        repair_helpers: Some(clay_d(k, layout.parity_shards, layout.repair_helpers)? as u16),
        sub_chunk_no: alpha as u32,
        shards: rows_to_node_chunks(&rows, n, alpha, row_len),
    })
}
/// Implements the clay reconstruct cpu step and keeps its validation and state transitions visible at the call site.
fn clay_reconstruct_cpu(
    shards: &[Option<Vec<u8>>],
    original_len: u64,
    layout: &ErasureLayout,
) -> Result<Vec<u8>> {
    let clay = clay_code(layout)?;
    if shards.len() != layout.n() {
        bail!("CLAY shard vector length mismatch")
    }
    let mut available = HashMap::new();
    let mut erasures = Vec::new();
    for (i, s) in shards.iter().enumerate() {
        match s {
            Some(v) => {
                available.insert(i, v.clone());
            }
            None => erasures.push(i),
        }
    }
    let mut out = clay
        .decode(&available, &erasures)
        .map_err(|e| anyhow!("CLAY decode failed: {e:?}"))?;
    out.truncate(original_len as usize);
    Ok(out)
}
/// Build and cache the inverse transform from any k complete surviving CLAY
/// nodes back to the k*alpha source rows. The structural matrix inversion is a
/// small control-plane operation; applying it across every byte column is the
/// bandwidth-heavy operation and is therefore suitable for CUDA.
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl", test))]
fn clay_decode_matrix(
    layout: &ErasureLayout,
    chosen: &[usize],
    max_bytes: usize,
) -> Result<(usize, Arc<Vec<u8>>)> {
    if chosen.len() != layout.data_shards {
        bail!("CLAY decode matrix requires exactly k survivors")
    }
    let d = clay_d(
        layout.data_shards,
        layout.parity_shards,
        layout.repair_helpers,
    )?;
    let key = (layout.data_shards, layout.parity_shards, d, chosen.to_vec());
    let cache = CLAY_DECODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&key).cloned() {
        let alpha = clay_code(layout)?.sub_chunk_no;
        return Ok((alpha, v));
    }
    let g = clay_generator(layout, max_bytes)?;
    let alpha = g.alpha;
    let source_rows = layout.data_shards * alpha;
    let matrix_bytes = source_rows
        .checked_mul(source_rows)
        .context("CLAY decode matrix size overflow")?;
    if matrix_bytes > max_bytes {
        bail!("CLAY decode matrix would require {matrix_bytes} bytes, over max_matrix_cache_bytes={max_bytes}")
    }
    let mut selected = Vec::with_capacity(matrix_bytes);
    for &node in chosen {
        if node >= layout.n() {
            bail!("CLAY survivor index out of range")
        }
        for sc in 0..alpha {
            let row = (node * alpha + sc) * source_rows;
            selected.extend_from_slice(&g.matrix[row..row + source_rows]);
        }
    }
    let inv = Arc::new(gf_matrix_inverse(&selected, source_rows)?);
    cache.lock().unwrap().insert(key, inv.clone());
    Ok((alpha, inv))
}
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl", test))]
/// Implements the clay reconstruct linearized with step and keeps its validation and state transitions visible at the call site.
fn clay_reconstruct_linearized_with<F>(
    shards: &[Option<Vec<u8>>],
    original_len: u64,
    layout: &ErasureLayout,
    max_bytes: usize,
    apply: F,
) -> Result<Vec<u8>>
where
    F: Fn(&[u8], usize, &[u8], usize, usize) -> Result<Vec<u8>>,
{
    if shards.len() != layout.n() {
        bail!("CLAY shard vector length mismatch")
    }
    let chosen = shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|_| i))
        .take(layout.data_shards)
        .collect::<Vec<_>>();
    if chosen.len() < layout.data_shards {
        bail!("need k={} CLAY nodes", layout.data_shards)
    }
    let (alpha, inv) = clay_decode_matrix(layout, &chosen, max_bytes)?;
    let chunk_len = shards[chosen[0]].as_ref().unwrap().len();
    if chunk_len == 0 || !chunk_len.is_multiple_of(alpha) {
        bail!("invalid CLAY chunk length")
    }
    if chosen
        .iter()
        .any(|&i| shards[i].as_ref().unwrap().len() != chunk_len)
    {
        bail!("inconsistent CLAY chunk lengths")
    }
    let row_len = chunk_len / alpha;
    let source_rows = layout.data_shards * alpha;
    let mut observed = Vec::with_capacity(source_rows * row_len);
    for &node in &chosen {
        observed.extend_from_slice(shards[node].as_ref().unwrap())
    }
    let mut out = apply(&observed, source_rows, inv.as_slice(), source_rows, row_len)?;
    out.truncate(original_len as usize);
    Ok(out)
}
/// Named type used to keep the ClayRepairMatrix data flow readable.
type ClayRepairMatrix = (usize, Vec<(usize, Vec<usize>)>, Arc<Vec<u8>>);
/// Implements the clay repair matrix step and keeps its validation and state transitions visible at the call site.
fn clay_repair_matrix(
    layout: &ErasureLayout,
    lost: usize,
    helpers: &[usize],
    max_bytes: usize,
) -> Result<ClayRepairMatrix> {
    let d = clay_d(
        layout.data_shards,
        layout.parity_shards,
        layout.repair_helpers,
    )?;
    let key = (
        layout.data_shards,
        layout.parity_shards,
        d,
        lost,
        helpers.to_vec(),
    );
    let clay = clay_code(layout)?;
    // Exact-repair coefficients are applied by Kagi's GF(256) engine too,
    // so require the same reference/field compatibility check used by the
    // CUDA encoder before deriving or caching a repair transform.
    let _ = clay_generator(layout, max_bytes)?;
    let alpha = clay.sub_chunk_no;
    let repair_map = clay
        .minimum_to_repair(lost, helpers)
        .map_err(|e| anyhow!("CLAY repair plan failed: {e:?}"))?;
    let beta_rows: usize = repair_map.iter().map(|(_, s)| s.len()).sum();
    let bytes = alpha
        .checked_mul(beta_rows)
        .context("CLAY repair matrix overflow")?;
    if bytes > max_bytes {
        bail!("CLAY CUDA repair matrix would require {bytes} bytes, over cache limit")
    }
    let cache = CLAY_REPAIR_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&key).cloned() {
        return Ok((alpha, repair_map, v));
    }
    let mut matrix = vec![0u8; alpha * beta_rows];
    // Derive the exact linear repair map by exciting each helper partial symbol.
    for col in 0..beta_rows {
        let mut partial: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut cursor = 0usize;
        for (helper, indices) in &repair_map {
            let mut buf = vec![0u8; indices.len() * 2];
            if col >= cursor && col < cursor + indices.len() {
                buf[(col - cursor) * 2] = 1;
            }
            cursor += indices.len();
            partial.insert(*helper, buf);
        }
        let recovered = clay
            .repair(lost, &partial, alpha * 2)
            .map_err(|e| anyhow!("CLAY repair-matrix derivation failed: {e:?}"))?;
        for out_sc in 0..alpha {
            matrix[out_sc * beta_rows + col] = recovered[out_sc * 2];
        }
    }
    let arc = Arc::new(matrix);
    cache.lock().unwrap().insert(key, arc.clone());
    Ok((alpha, repair_map, arc))
}
#[cfg(test)]
/// Implements the clay repair with step and keeps its validation and state transitions visible at the call site.
fn clay_repair_with<F>(
    shards: &[Option<Vec<u8>>],
    lost: usize,
    layout: &ErasureLayout,
    max_bytes: usize,
    apply: F,
) -> Result<Vec<u8>>
where
    F: Fn(&[u8], usize, &[u8], usize, usize) -> Result<Vec<u8>>,
{
    let clay = clay_code(layout)?;
    if shards.len() != layout.n() || lost >= layout.n() {
        bail!("invalid CLAY repair request")
    }
    let available: Vec<usize> = shards
        .iter()
        .enumerate()
        .filter(|(i, s)| *i != lost && s.is_some())
        .map(|(i, _)| i)
        .collect();
    let d = clay.d;
    if available.len() < d {
        bail!("CLAY exact repair needs d={d} helpers")
    }
    let helpers = available[..d].to_vec();
    let (alpha, repair_map, coeff) = clay_repair_matrix(layout, lost, &helpers, max_bytes)?;
    let chunk_len = shards[helpers[0]].as_ref().unwrap().len();
    if !chunk_len.is_multiple_of(alpha) {
        bail!("invalid CLAY chunk length")
    }
    let row_len = chunk_len / alpha;
    let mut input = Vec::new();
    for (helper, indices) in &repair_map {
        let chunk = shards[*helper]
            .as_ref()
            .context("CLAY helper disappeared")?;
        for &sc in indices {
            input.extend_from_slice(&chunk[sc * row_len..(sc + 1) * row_len]);
        }
    }
    let in_rows: usize = repair_map.iter().map(|(_, s)| s.len()).sum();
    apply(&input, in_rows, coeff.as_slice(), alpha, row_len)
}
/// Implements the clay exact repair plan step and keeps its validation and state transitions visible at the call site.
fn clay_exact_repair_plan(
    layout: &ErasureLayout,
    lost: usize,
    available: &[usize],
    chunk_len: usize,
    max_bytes: usize,
) -> Result<ExactRepairPlan> {
    let clay = clay_code(layout)?;
    if lost >= layout.n() || chunk_len == 0 || !chunk_len.is_multiple_of(clay.sub_chunk_no) {
        bail!("invalid CLAY exact-repair request")
    }
    let helpers: Vec<usize> = available
        .iter()
        .copied()
        .filter(|&h| h != lost && h < layout.n())
        .take(clay.d)
        .collect();
    if helpers.len() != clay.d {
        bail!("CLAY exact repair needs d={} available helpers", clay.d)
    }
    let (alpha, repair_map, coeff) = clay_repair_matrix(layout, lost, &helpers, max_bytes)?;
    let input_rows: usize = repair_map.iter().map(|(_, s)| s.len()).sum();
    let fetches = repair_map
        .into_iter()
        .map(|(shard, indices)| RepairFetch::SubChunks {
            shard,
            alpha,
            indices,
        })
        .collect();
    Ok(ExactRepairPlan {
        chunk_len,
        row_len: chunk_len / alpha,
        fetches,
        input_rows,
        output_rows: alpha,
        recovery_coeff: coeff.as_ref().clone(),
    })
}
// -----------------------------------------------------------------------------
// CUDA generic GF(256) matrix engine.  All CUDA codec paths reduce their hot
// byte-column transforms to this ABI; structure/planning remains on the CPU.
// -----------------------------------------------------------------------------
#[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
mod gpu {
    use super::*;
    use std::ffi::c_int;
    #[cfg(feature = "cuda")]
    extern "C" {
        fn keyspace_cuda_available() -> c_int;
        fn keyspace_cuda_matrix_apply(
            input: *const u8,
            in_rows: usize,
            coeff: *const u8,
            out_rows: usize,
            row_len: usize,
            output: *mut u8,
        ) -> c_int;
    }
    #[cfg(feature = "hip")]
    extern "C" {
        fn kagi_hip_available() -> c_int;
        fn kagi_hip_matrix_apply(
            input: *const u8,
            in_rows: usize,
            coeff: *const u8,
            out_rows: usize,
            row_len: usize,
            output: *mut u8,
        ) -> c_int;
    }
    #[cfg(feature = "opencl")]
    extern "C" {
        fn kagi_opencl_available() -> c_int;
        fn kagi_opencl_matrix_apply(
            input: *const u8,
            in_rows: usize,
            coeff: *const u8,
            out_rows: usize,
            row_len: usize,
            output: *mut u8,
        ) -> c_int;
    }
    pub fn available(kind: BackendKind) -> bool {
        #[cfg(feature = "cuda")]
        if matches!(kind, BackendKind::Auto | BackendKind::Cuda)
            && unsafe { keyspace_cuda_available() != 0 }
        {
            return true;
        }
        #[cfg(feature = "hip")]
        if matches!(kind, BackendKind::Auto | BackendKind::Hip)
            && unsafe { kagi_hip_available() != 0 }
        {
            return true;
        }
        #[cfg(feature = "opencl")]
        if matches!(kind, BackendKind::Auto | BackendKind::Opencl)
            && unsafe { kagi_opencl_available() != 0 }
        {
            return true;
        }
        false
    }
    pub fn matrix_apply(
        kind: BackendKind,
        input: &[u8],
        in_rows: usize,
        coeff: &[u8],
        out_rows: usize,
        row_len: usize,
    ) -> Result<Vec<u8>> {
        if Some(input.len()) != in_rows.checked_mul(row_len)
            || Some(coeff.len()) != out_rows.checked_mul(in_rows)
        {
            bail!("GPU GF matrix shape mismatch")
        }
        let mut out = vec![
            0u8;
            out_rows
                .checked_mul(row_len)
                .context("GF output size overflow")?
        ];
        let mut rc = -1;
        #[cfg(feature = "cuda")]
        if matches!(kind, BackendKind::Auto | BackendKind::Cuda)
            && unsafe { keyspace_cuda_available() != 0 }
        {
            rc = unsafe {
                keyspace_cuda_matrix_apply(
                    input.as_ptr(),
                    in_rows,
                    coeff.as_ptr(),
                    out_rows,
                    row_len,
                    out.as_mut_ptr(),
                )
            };
        }
        #[cfg(feature = "hip")]
        if rc != 0
            && matches!(kind, BackendKind::Auto | BackendKind::Hip)
            && unsafe { kagi_hip_available() != 0 }
        {
            rc = unsafe {
                kagi_hip_matrix_apply(
                    input.as_ptr(),
                    in_rows,
                    coeff.as_ptr(),
                    out_rows,
                    row_len,
                    out.as_mut_ptr(),
                )
            };
        }
        #[cfg(feature = "opencl")]
        if rc != 0
            && matches!(kind, BackendKind::Auto | BackendKind::Opencl)
            && unsafe { kagi_opencl_available() != 0 }
        {
            rc = unsafe {
                kagi_opencl_matrix_apply(
                    input.as_ptr(),
                    in_rows,
                    coeff.as_ptr(),
                    out_rows,
                    row_len,
                    out.as_mut_ptr(),
                )
            };
        }
        if rc != 0 {
            bail!("GPU GF matrix apply failed ({rc})")
        }
        Ok(out)
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct ErasureMetricsSnapshot {
    pub cpu_bytes: u64,
    pub gpu_bytes: u64,
    pub gpu_fallbacks: u64,
    pub gpu_inflight: u64,
    pub gpu_repairs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccelerationStatus {
    pub requested: BackendKind,
    pub cuda_compiled: bool,
    pub hip_compiled: bool,
    pub opencl_compiled: bool,
    pub isa_l_compiled: bool,
    pub ipp_compiled: bool,
    pub aocl_compiled: bool,
    pub selected_gpu_available: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
}

#[cfg(target_arch = "x86_64")]
fn cpu_feature_avx2() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}
#[cfg(not(target_arch = "x86_64"))]
fn cpu_feature_avx2() -> bool {
    false
}
#[cfg(target_arch = "x86_64")]
fn cpu_feature_avx512f() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
}
#[cfg(not(target_arch = "x86_64"))]
fn cpu_feature_avx512f() -> bool {
    false
}
#[cfg(target_arch = "x86_64")]
fn cpu_feature_avx512bw() -> bool {
    std::arch::is_x86_feature_detected!("avx512bw")
}
#[cfg(not(target_arch = "x86_64"))]
fn cpu_feature_avx512bw() -> bool {
    false
}

#[derive(Default)]
/// Kagi state or configuration used by the ErasureMetrics path.
pub struct ErasureMetrics {
    pub cpu_bytes: AtomicU64,
    #[cfg_attr(
        not(any(feature = "cuda", feature = "hip", feature = "opencl")),
        allow(dead_code)
    )]
    pub gpu_bytes: AtomicU64,
    #[cfg_attr(
        not(any(feature = "cuda", feature = "hip", feature = "opencl")),
        allow(dead_code)
    )]
    pub gpu_fallbacks: AtomicU64,
    pub gpu_inflight: AtomicU64,
    #[cfg_attr(
        not(any(feature = "cuda", feature = "hip", feature = "opencl")),
        allow(dead_code)
    )]
    // The exact-repair trait entry point is not used by every daemon build.
    #[allow(dead_code)]
    pub gpu_repairs: AtomicU64,
}
/// Kagi state or configuration used by the AdaptiveBackend path.
pub struct AdaptiveBackend {
    cfg: ErasureConfig,
    cpu_rs: Arc<CpuBackend>,
    metrics: Arc<ErasureMetrics>,
}
impl AdaptiveBackend {
    pub fn new(cfg: ErasureConfig) -> Self {
        Self {
            cfg,
            cpu_rs: Arc::new(CpuBackend),
            metrics: Arc::new(ErasureMetrics::default()),
        }
    }

    pub fn metrics_snapshot(&self) -> ErasureMetricsSnapshot {
        ErasureMetricsSnapshot {
            cpu_bytes: self.metrics.cpu_bytes.load(Ordering::Relaxed),
            gpu_bytes: self.metrics.gpu_bytes.load(Ordering::Relaxed),
            gpu_fallbacks: self.metrics.gpu_fallbacks.load(Ordering::Relaxed),
            gpu_inflight: self.metrics.gpu_inflight.load(Ordering::Relaxed),
            gpu_repairs: self.metrics.gpu_repairs.load(Ordering::Relaxed),
        }
    }

    pub fn acceleration_status(&self) -> AccelerationStatus {
        #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
        let selected_gpu_available = gpu::available(self.cfg.backend);
        #[cfg(not(any(feature = "cuda", feature = "hip", feature = "opencl")))]
        let selected_gpu_available = false;

        AccelerationStatus {
            requested: self.cfg.backend,
            cuda_compiled: cfg!(feature = "cuda"),
            hip_compiled: cfg!(feature = "hip"),
            opencl_compiled: cfg!(feature = "opencl"),
            isa_l_compiled: cfg!(feature = "isa-l"),
            ipp_compiled: cfg!(feature = "ipp"),
            aocl_compiled: cfg!(feature = "aocl"),
            selected_gpu_available,
            avx2: cpu_feature_avx2(),
            avx512f: cpu_feature_avx512f(),
            avx512bw: cpu_feature_avx512bw(),
        }
    }
    fn configured_layout(&self, k: usize, m: usize) -> Result<ErasureLayout> {
        let l = ErasureLayout {
            scheme: self.cfg.scheme,
            data_shards: k,
            parity_shards: m,
            repair_helpers: self.cfg.repair_helpers,
        };
        l.validate()?;
        Ok(l)
    }
    fn can_gpu(&self, bytes: usize) -> bool {
        if self.cfg.backend == BackendKind::Cpu || bytes < self.cfg.gpu_threshold_bytes {
            return false;
        }
        #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
        {
            gpu::available(self.cfg.backend)
        }
        #[cfg(not(any(feature = "cuda", feature = "hip", feature = "opencl")))]
        {
            false
        }
    }
    fn try_gpu_slot(&self) -> bool {
        let q = self.metrics.gpu_inflight.fetch_add(1, Ordering::AcqRel);
        if q < self.cfg.max_gpu_inflight {
            true
        } else {
            self.metrics.gpu_inflight.fetch_sub(1, Ordering::AcqRel);
            false
        }
    }
    fn release_gpu_slot(&self) {
        self.metrics.gpu_inflight.fetch_sub(1, Ordering::AcqRel);
    }
}
#[async_trait]
impl ErasureBackend for AdaptiveBackend {
    fn default_layout(&self, k: usize, m: usize) -> Result<ErasureLayout> {
        self.configured_layout(k, m)
    }
    fn exact_repair_plan(
        &self,
        available: &[usize],
        lost: usize,
        chunk_len: usize,
        layout: &ErasureLayout,
    ) -> Result<Option<ExactRepairPlan>> {
        layout.validate()?;
        Ok(match layout.scheme {
            ErasureScheme::ReedSolomon => None,
            ErasureScheme::Msr => {
                let pm = pm_layout(layout.data_shards, layout.parity_shards)?;
                Some(pm_exact_repair_plan(
                    pm.as_ref(),
                    lost,
                    available,
                    chunk_len,
                )?)
            }
            ErasureScheme::Clay => Some(clay_exact_repair_plan(
                layout,
                lost,
                available,
                chunk_len,
                self.cfg.max_matrix_cache_bytes,
            )?),
        })
    }
    async fn linear_transform(
        &self,
        input: &[u8],
        in_rows: usize,
        coeff: &[u8],
        out_rows: usize,
        row_len: usize,
    ) -> Result<Vec<u8>> {
        #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
        if self.can_gpu(input.len()) && self.try_gpu_slot() {
            let r = gpu::matrix_apply(self.cfg.backend, input, in_rows, coeff, out_rows, row_len);
            self.release_gpu_slot();
            if let Ok(v) = r {
                self.metrics
                    .gpu_bytes
                    .fetch_add(input.len() as u64, Ordering::Relaxed);
                return Ok(v);
            }
            self.metrics.gpu_fallbacks.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics
            .cpu_bytes
            .fetch_add(input.len() as u64, Ordering::Relaxed);
        gf_matrix_apply_cpu(input, in_rows, coeff, out_rows, row_len)
    }
    async fn encode_layout(&self, data: &[u8], layout: &ErasureLayout) -> Result<EncodedShards> {
        layout.validate()?;
        let use_gpu = self.can_gpu(data.len()) && self.try_gpu_slot();
        if use_gpu {
            #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
            {
                let r = match layout.scheme {
                    ErasureScheme::ReedSolomon => {
                        // Reuse the RS generator by encoding basis bytes; this preserves byte-for-byte compatibility.
                        let (k, m) = (layout.data_shards, layout.parity_shards);
                        let rs = ReedSolomon::new(k, m)?;
                        let mut coeff = vec![0u8; k * m];
                        for d in 0..k {
                            let mut basis = vec![vec![0u8; 1]; k + m];
                            basis[d][0] = 1;
                            rs.encode(&mut basis)?;
                            for p in 0..m {
                                coeff[p * k + d] = basis[k + p][0];
                            }
                        }
                        let shard_len = data.len().div_ceil(k).max(1);
                        let input = pack_source_rows(data, k, shard_len);
                        let mut full_coeff = vec![0u8; (k + m) * k];
                        for i in 0..k {
                            full_coeff[i * k + i] = 1;
                        }
                        full_coeff[k * k..].copy_from_slice(&coeff);
                        gpu::matrix_apply(
                            self.cfg.backend,
                            &input,
                            k,
                            &full_coeff,
                            k + m,
                            shard_len,
                        )
                        .map(|rows| EncodedShards {
                            original_len: data.len() as u64,
                            data_shards: k as u16,
                            parity_shards: m as u16,
                            scheme: ErasureScheme::ReedSolomon,
                            repair_helpers: None,
                            sub_chunk_no: 1,
                            shards: rows.chunks_exact(shard_len).map(|x| x.to_vec()).collect(),
                        })
                    }
                    ErasureScheme::Msr => {
                        let p = pm_layout(layout.data_shards, layout.parity_shards)?;
                        pm_encode_with(data, &p, |input, in_rows, coeff, out_rows, row_len| {
                            gpu::matrix_apply(
                                self.cfg.backend,
                                input,
                                in_rows,
                                coeff,
                                out_rows,
                                row_len,
                            )
                        })
                    }
                    ErasureScheme::Clay => clay_encode_linearized_with(
                        data,
                        layout,
                        self.cfg.max_matrix_cache_bytes,
                        |input, in_rows, coeff, out_rows, row_len| {
                            gpu::matrix_apply(
                                self.cfg.backend,
                                input,
                                in_rows,
                                coeff,
                                out_rows,
                                row_len,
                            )
                        },
                    ),
                };
                self.release_gpu_slot();
                if let Ok(v) = r {
                    self.metrics
                        .gpu_bytes
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    return Ok(v);
                }
                self.metrics.gpu_fallbacks.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(not(any(feature = "cuda", feature = "hip", feature = "opencl")))]
            self.release_gpu_slot();
        }
        self.metrics
            .cpu_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        match layout.scheme {
            ErasureScheme::ReedSolomon => self.cpu_rs.encode_layout(data, layout).await,
            ErasureScheme::Msr => {
                let p = pm_layout(layout.data_shards, layout.parity_shards)?;
                pm_encode_with(data, &p, gf_matrix_apply_cpu)
            }
            ErasureScheme::Clay => {
                let clay = clay_code(layout)?;
                let d = clay.d;
                let shards = clay.encode(data);
                Ok(EncodedShards {
                    original_len: data.len() as u64,
                    data_shards: layout.data_shards as u16,
                    parity_shards: layout.parity_shards as u16,
                    scheme: ErasureScheme::Clay,
                    repair_helpers: Some(d as u16),
                    sub_chunk_no: clay.sub_chunk_no as u32,
                    shards,
                })
            }
        }
    }
    async fn reconstruct_layout(
        &self,
        shards: &mut [Option<Vec<u8>>],
        original_len: u64,
        layout: &ErasureLayout,
    ) -> Result<Vec<u8>> {
        layout.validate()?;
        match layout.scheme {
            ErasureScheme::ReedSolomon => {
                self.cpu_rs
                    .reconstruct_layout(shards, original_len, layout)
                    .await
            }
            ErasureScheme::Clay => {
                #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
                if self.can_gpu(original_len as usize) && self.try_gpu_slot() {
                    let r = clay_reconstruct_linearized_with(
                        shards,
                        original_len,
                        layout,
                        self.cfg.max_matrix_cache_bytes,
                        |input, in_rows, coeff, out_rows, row_len| {
                            gpu::matrix_apply(
                                self.cfg.backend,
                                input,
                                in_rows,
                                coeff,
                                out_rows,
                                row_len,
                            )
                        },
                    );
                    self.release_gpu_slot();
                    if let Ok(v) = r {
                        self.metrics
                            .gpu_bytes
                            .fetch_add(original_len, Ordering::Relaxed);
                        return Ok(v);
                    }
                    self.metrics.gpu_fallbacks.fetch_add(1, Ordering::Relaxed);
                }
                clay_reconstruct_cpu(shards, original_len, layout)
            }
            ErasureScheme::Msr => {
                let p = pm_layout(layout.data_shards, layout.parity_shards)?;
                #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
                if self.can_gpu(original_len as usize) && self.try_gpu_slot() {
                    let r = pm_reconstruct_with(
                        shards,
                        original_len,
                        &p,
                        |input, in_rows, coeff, out_rows, row_len| {
                            gpu::matrix_apply(
                                self.cfg.backend,
                                input,
                                in_rows,
                                coeff,
                                out_rows,
                                row_len,
                            )
                        },
                    );
                    self.release_gpu_slot();
                    if let Ok(v) = r {
                        self.metrics
                            .gpu_bytes
                            .fetch_add(original_len, Ordering::Relaxed);
                        return Ok(v);
                    }
                    self.metrics.gpu_fallbacks.fetch_add(1, Ordering::Relaxed);
                }
                pm_reconstruct_with(shards, original_len, &p, gf_matrix_apply_cpu)
            }
        }
    }
    #[cfg(test)]
    async fn repair_shard_layout(
        &self,
        shards: &[Option<Vec<u8>>],
        lost: usize,
        layout: &ErasureLayout,
    ) -> Result<Vec<u8>> {
        layout.validate()?;
        #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
        let shard_bytes = shards.iter().flatten().next().map(|x| x.len()).unwrap_or(0);
        #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
        if self.can_gpu(shard_bytes) && self.try_gpu_slot() {
            let r = match layout.scheme {
                ErasureScheme::ReedSolomon => {
                    Err(anyhow!("RS exact-repair CUDA path uses normal reconstruct"))
                }
                ErasureScheme::Msr => {
                    let p = pm_layout(layout.data_shards, layout.parity_shards)?;
                    pm_repair_with(
                        shards,
                        lost,
                        &p,
                        |input, in_rows, coeff, out_rows, row_len| {
                            gpu::matrix_apply(
                                self.cfg.backend,
                                input,
                                in_rows,
                                coeff,
                                out_rows,
                                row_len,
                            )
                        },
                    )
                }
                ErasureScheme::Clay => clay_repair_with(
                    shards,
                    lost,
                    layout,
                    self.cfg.max_matrix_cache_bytes,
                    |input, in_rows, coeff, out_rows, row_len| {
                        gpu::matrix_apply(
                            self.cfg.backend,
                            input,
                            in_rows,
                            coeff,
                            out_rows,
                            row_len,
                        )
                    },
                ),
            };
            self.release_gpu_slot();
            if let Ok(v) = r {
                self.metrics.gpu_repairs.fetch_add(1, Ordering::Relaxed);
                return Ok(v);
            }
            self.metrics.gpu_fallbacks.fetch_add(1, Ordering::Relaxed);
        }
        match layout.scheme {
            ErasureScheme::ReedSolomon => {
                self.cpu_rs.repair_shard_layout(shards, lost, layout).await
            }
            ErasureScheme::Msr => {
                let p = pm_layout(layout.data_shards, layout.parity_shards)?;
                pm_repair_with(shards, lost, &p, gf_matrix_apply_cpu)
            }
            ErasureScheme::Clay => clay_repair_with(
                shards,
                lost,
                layout,
                self.cfg.max_matrix_cache_bytes,
                gf_matrix_apply_cpu,
            ),
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn matrix_rejects_overflowing_dimensions() {
        assert!(super::gf_matrix_apply_cpu(&[], usize::MAX, &[], 2, 2).is_err());
        assert!(super::gf_matrix_apply_cpu(&[], 0, &[], usize::MAX, 2).is_err());
    }
    use super::*;
    #[tokio::test]
    async fn reed_solomon_roundtrip_with_losses() {
        let b = CpuBackend;
        let src = vec![0x5a; 10003];
        let l = b.default_layout(6, 3).unwrap();
        let e = b.encode_layout(&src, &l).await.unwrap();
        let mut s = e.shards.into_iter().map(Some).collect::<Vec<_>>();
        s[1] = None;
        s[7] = None;
        assert_eq!(
            b.reconstruct_layout(&mut s, e.original_len, &l)
                .await
                .unwrap(),
            src
        );
    }
    #[test]
    fn gf_inverse_roundtrip() {
        // Vandermonde rows over distinct non-zero field elements are invertible.
        let xs = [1u8, 2, 3];
        let mut a = Vec::with_capacity(9);
        for x in xs {
            for p in 0..3 {
                a.push(gf_pow(x, p));
            }
        }
        let inv = gf_matrix_inverse(&a, 3).unwrap();
        let mut prod = vec![0u8; 9];
        for r in 0..3 {
            for c in 0..3 {
                for x in 0..3 {
                    prod[r * 3 + c] ^= gf_mul(a[r * 3 + x], inv[x * 3 + c]);
                }
            }
        }
        assert_eq!(prod, vec![1, 0, 0, 0, 1, 0, 0, 0, 1]);
    }
    #[tokio::test]
    async fn product_matrix_msr_roundtrip_and_exact_repair() {
        let b = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(6),
            ..Default::default()
        });
        let l = b.default_layout(4, 3).unwrap();
        let src: Vec<u8> = (0..8193).map(|x| (x * 17) as u8).collect();
        let e = b.encode_layout(&src, &l).await.unwrap();
        let mut s = e.shards.iter().cloned().map(Some).collect::<Vec<_>>();
        let want = e.shards[2].clone();
        s[2] = None;
        let repaired = b.repair_shard_layout(&s, 2, &l).await.unwrap();
        assert_eq!(repaired, want);
        s[5] = None;
        let out = b
            .reconstruct_layout(&mut s, src.len() as u64, &l)
            .await
            .unwrap();
        assert_eq!(out, src);
    }
    #[tokio::test]
    async fn clay_roundtrip_and_exact_repair() {
        let b = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
            ..Default::default()
        });
        let l = b.default_layout(4, 2).unwrap();
        let src: Vec<u8> = (0..4097).map(|x| (x * 29) as u8).collect();
        let e = b.encode_layout(&src, &l).await.unwrap();
        let mut s = e.shards.iter().cloned().map(Some).collect::<Vec<_>>();
        let want = e.shards[0].clone();
        s[0] = None;
        assert_eq!(b.repair_shard_layout(&s, 0, &l).await.unwrap(), want);
        s[5] = None;
        assert_eq!(
            b.reconstruct_layout(&mut s, src.len() as u64, &l)
                .await
                .unwrap(),
            src
        );
    }
    #[test]
    fn runtime_default_prefers_clay() {
        let c = ErasureConfig::default();
        assert_eq!(c.scheme, ErasureScheme::Clay);
    }
    #[test]
    fn old_manifest_scheme_default_remains_reed_solomon() {
        #[derive(Deserialize)]
        struct LegacyCompat {
            #[serde(default)]
            scheme: ErasureScheme,
        }
        let x: LegacyCompat = serde_json::from_str("{}").unwrap();
        assert_eq!(x.scheme, ErasureScheme::ReedSolomon);
    }
    #[test]
    fn clay_requires_repairable_geometry() {
        let l = ErasureLayout {
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 1,
            repair_helpers: None,
        };
        assert!(l.validate().is_err());
    }
    #[test]
    fn product_matrix_requires_canonical_helper_count() {
        let l = ErasureLayout {
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(5),
        };
        assert!(l.validate().is_err());
    }
    #[test]
    fn clay_linearized_encoder_matches_reference() {
        let l = ErasureLayout {
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
        };
        let src: Vec<u8> = (0..1025).map(|x| (x * 31) as u8).collect();
        let ref_chunks = clay_code(&l).unwrap().encode(&src);
        let linear = clay_encode_linearized_with(&src, &l, 16 << 20, gf_matrix_apply_cpu).unwrap();
        assert_eq!(linear.shards, ref_chunks);
    }
    #[test]
    fn clay_linearized_decoder_matches_reference() {
        let l = ErasureLayout {
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
        };
        let src: Vec<u8> = (0..5003).map(|x| (x * 11) as u8).collect();
        let e = clay_encode_linearized_with(&src, &l, 16 << 20, gf_matrix_apply_cpu).unwrap();
        let mut shards = e.shards.into_iter().map(Some).collect::<Vec<_>>();
        shards[0] = None;
        shards[5] = None;
        assert_eq!(
            clay_reconstruct_linearized_with(
                &shards,
                src.len() as u64,
                &l,
                16 << 20,
                gf_matrix_apply_cpu
            )
            .unwrap(),
            src
        );
    }
    #[tokio::test]
    async fn product_matrix_exact_plan_downloads_one_projection_per_helper() {
        let b = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(6),
            ..Default::default()
        });
        let l = b.default_layout(4, 3).unwrap();
        let src: Vec<u8> = (0..16391).map(|x| (x * 19) as u8).collect();
        let e = b.encode_layout(&src, &l).await.unwrap();
        let lost = 3usize;
        let available = (0..e.shards.len())
            .filter(|&i| i != lost)
            .collect::<Vec<_>>();
        let plan = b
            .exact_repair_plan(&available, lost, e.shards[lost].len(), &l)
            .unwrap()
            .unwrap();
        assert_eq!(plan.fetches.len(), 6);
        assert_eq!(plan.input_rows, 6);
        assert_eq!(plan.output_rows, 3);
        let mut payloads = Vec::new();
        for fetch in &plan.fetches {
            match fetch {
                RepairFetch::Projection { shard, rows, coeff } => {
                    assert_eq!(coeff.len() / rows, 1);
                    let chunk = &e.shards[*shard];
                    let row_len = chunk.len() / rows;
                    payloads.push(gf_matrix_apply_cpu(chunk, *rows, coeff, 1, row_len).unwrap());
                }
                _ => panic!("MSR plan must request projections"),
            }
        }
        assert_eq!(
            b.apply_exact_repair(&plan, &payloads).await.unwrap(),
            e.shards[lost]
        );
    }
    fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
        fn visit(
            start: usize,
            n: usize,
            k: usize,
            cur: &mut Vec<usize>,
            out: &mut Vec<Vec<usize>>,
        ) {
            if cur.len() == k {
                out.push(cur.clone());
                return;
            }
            let need = k - cur.len();
            for i in start..=n - need {
                cur.push(i);
                visit(i + 1, n, k, cur, out);
                cur.pop();
            }
        }
        let mut out = Vec::new();
        if k <= n {
            visit(0, n, k, &mut Vec::new(), &mut out);
        }
        out
    }
    #[tokio::test]
    async fn product_matrix_recovers_from_every_k_subset_and_repairs_every_node() {
        let b = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(6),
            ..Default::default()
        });
        let l = b.default_layout(4, 3).unwrap();
        let src: Vec<u8> = (0..6001).map(|x| (x * 43 + 7) as u8).collect();
        let encoded = b.encode_layout(&src, &l).await.unwrap();
        for keep in combinations(7, 4) {
            let mut shards = vec![None; 7];
            for &i in &keep {
                shards[i] = Some(encoded.shards[i].clone());
            }
            assert_eq!(
                b.reconstruct_layout(&mut shards, src.len() as u64, &l)
                    .await
                    .unwrap(),
                src,
                "PM-MSR failed survivor set {keep:?}"
            );
        }
        for lost in 0..7 {
            let mut shards = encoded.shards.iter().cloned().map(Some).collect::<Vec<_>>();
            shards[lost] = None;
            assert_eq!(
                b.repair_shard_layout(&shards, lost, &l).await.unwrap(),
                encoded.shards[lost],
                "PM-MSR failed exact repair for node {lost}"
            );
        }
    }
    #[tokio::test]
    async fn clay_recovers_from_every_k_subset_and_repairs_every_node() {
        let b = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
            ..Default::default()
        });
        let l = b.default_layout(4, 2).unwrap();
        let src: Vec<u8> = (0..6007).map(|x| (x * 47 + 11) as u8).collect();
        let encoded = b.encode_layout(&src, &l).await.unwrap();
        for keep in combinations(6, 4) {
            let mut shards = vec![None; 6];
            for &i in &keep {
                shards[i] = Some(encoded.shards[i].clone());
            }
            assert_eq!(
                b.reconstruct_layout(&mut shards, src.len() as u64, &l)
                    .await
                    .unwrap(),
                src,
                "CLAY failed survivor set {keep:?}"
            );
        }
        for lost in 0..6 {
            let mut shards = encoded.shards.iter().cloned().map(Some).collect::<Vec<_>>();
            shards[lost] = None;
            assert_eq!(
                b.repair_shard_layout(&shards, lost, &l).await.unwrap(),
                encoded.shards[lost],
                "CLAY failed exact repair for node {lost}"
            );
        }
    }
    #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
    #[tokio::test]
    async fn gpu_product_matrix_matches_cpu_reference() {
        if !gpu::available(BackendKind::Auto) {
            assert!(
                std::env::var_os("KAGI_REQUIRE_GPU_TESTS").is_none(),
                "GPU execution required but no compiled backend has an available device"
            );
            eprintln!("GPU execution skipped: no available device");
            return;
        }
        let l = ErasureLayout {
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(6),
        };
        let src: Vec<u8> = (0..2_000_003).map(|x| (x * 7) as u8).collect();
        let cpu = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(6),
            gpu_threshold_bytes: 0,
            ..Default::default()
        });
        let gpu = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Auto,
            scheme: ErasureScheme::Msr,
            data_shards: 4,
            parity_shards: 3,
            repair_helpers: Some(6),
            gpu_threshold_bytes: 0,
            ..Default::default()
        });
        let a = cpu.encode_layout(&src, &l).await.unwrap();
        let b = gpu.encode_layout(&src, &l).await.unwrap();
        assert!(gpu.metrics.gpu_bytes.load(Ordering::Relaxed) > 0);
        assert_eq!(gpu.metrics.gpu_fallbacks.load(Ordering::Relaxed), 0);
        assert_eq!(a.shards, b.shards);
        let mut shards = b.shards.into_iter().map(Some).collect::<Vec<_>>();
        shards[1] = None;
        shards[5] = None;
        assert_eq!(
            gpu.reconstruct_layout(&mut shards, src.len() as u64, &l)
                .await
                .unwrap(),
            src
        );
    }
    #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
    #[tokio::test]
    async fn gpu_clay_matches_reference_and_reconstructs() {
        if !gpu::available(BackendKind::Auto) {
            assert!(
                std::env::var_os("KAGI_REQUIRE_GPU_TESTS").is_none(),
                "GPU execution required but no compiled backend has an available device"
            );
            eprintln!("GPU execution skipped: no available device");
            return;
        }
        let l = ErasureLayout {
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
        };
        let src: Vec<u8> = (0..2_000_011).map(|x| (x * 13) as u8).collect();
        let gpu = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Auto,
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
            gpu_threshold_bytes: 0,
            ..Default::default()
        });
        let encoded = gpu.encode_layout(&src, &l).await.unwrap();
        assert!(gpu.metrics.gpu_bytes.load(Ordering::Relaxed) > 0);
        assert_eq!(gpu.metrics.gpu_fallbacks.load(Ordering::Relaxed), 0);
        assert_eq!(encoded.shards, clay_code(&l).unwrap().encode(&src));
        let mut shards = encoded.shards.into_iter().map(Some).collect::<Vec<_>>();
        shards[0] = None;
        shards[4] = None;
        assert_eq!(
            gpu.reconstruct_layout(&mut shards, src.len() as u64, &l)
                .await
                .unwrap(),
            src
        );
    }
    #[cfg(any(feature = "cuda", feature = "hip", feature = "opencl"))]
    #[tokio::test]
    async fn gpu_exact_repair_matches_persisted_chunks() {
        if !gpu::available(BackendKind::Auto) {
            assert!(
                std::env::var_os("KAGI_REQUIRE_GPU_TESTS").is_none(),
                "GPU execution required but no compiled backend has an available device"
            );
            eprintln!("GPU execution skipped: no available device");
            return;
        }
        let cases = [
            ErasureLayout {
                scheme: ErasureScheme::Msr,
                data_shards: 4,
                parity_shards: 3,
                repair_helpers: Some(6),
            },
            ErasureLayout {
                scheme: ErasureScheme::Clay,
                data_shards: 4,
                parity_shards: 2,
                repair_helpers: Some(5),
            },
        ];
        for l in cases {
            let gpu = AdaptiveBackend::new(ErasureConfig {
                backend: BackendKind::Auto,
                scheme: l.scheme,
                data_shards: l.data_shards,
                parity_shards: l.parity_shards,
                repair_helpers: l.repair_helpers,
                gpu_threshold_bytes: 0,
                ..Default::default()
            });
            let src: Vec<u8> = (0..2_000_017).map(|x| (x * 37 + 3) as u8).collect();
            let encoded = gpu.encode_layout(&src, &l).await.unwrap();
            assert!(gpu.metrics.gpu_bytes.load(Ordering::Relaxed) > 0);
            assert_eq!(gpu.metrics.gpu_fallbacks.load(Ordering::Relaxed), 0);
            for lost in [0usize, encoded.shards.len() - 1] {
                let mut shards = encoded.shards.iter().cloned().map(Some).collect::<Vec<_>>();
                shards[lost] = None;
                assert_eq!(
                    gpu.repair_shard_layout(&shards, lost, &l).await.unwrap(),
                    encoded.shards[lost]
                );
            }
        }
    }
    #[tokio::test]
    async fn clay_exact_plan_fetches_only_minimum_subchunks() {
        let b = AdaptiveBackend::new(ErasureConfig {
            backend: BackendKind::Cpu,
            scheme: ErasureScheme::Clay,
            data_shards: 4,
            parity_shards: 2,
            repair_helpers: Some(5),
            ..Default::default()
        });
        let l = b.default_layout(4, 2).unwrap();
        let clay = clay_code(&l).unwrap();
        let src: Vec<u8> = (0..8197).map(|x| (x * 23) as u8).collect();
        let e = b.encode_layout(&src, &l).await.unwrap();
        let lost = 1usize;
        let available = (0..e.shards.len())
            .filter(|&i| i != lost)
            .collect::<Vec<_>>();
        let plan = b
            .exact_repair_plan(&available, lost, e.shards[lost].len(), &l)
            .unwrap()
            .unwrap();
        assert_eq!(plan.fetches.len(), clay.d);
        let mut payloads = Vec::new();
        for fetch in &plan.fetches {
            match fetch {
                RepairFetch::SubChunks {
                    shard,
                    alpha,
                    indices,
                } => {
                    assert!(!indices.is_empty());
                    assert!(indices.len() < *alpha);
                    let chunk = &e.shards[*shard];
                    let row_len = chunk.len() / alpha;
                    let mut part = Vec::new();
                    for &idx in indices {
                        part.extend_from_slice(&chunk[idx * row_len..(idx + 1) * row_len]);
                    }
                    payloads.push(part);
                }
                _ => panic!("CLAY plan must request subchunks"),
            }
        }
        assert_eq!(
            b.apply_exact_repair(&plan, &payloads).await.unwrap(),
            e.shards[lost]
        );
    }
}
