// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi distributed object data plane.
//!
//! This module owns immutable object versions, fragment placement, checksums, metadata
//! encryption, replicated and erasure-coded writes, reads, repair, and peer fragment RPC.
//! Placement is deterministic for a fixed cluster configuration so every healthy node can
//! independently derive the same candidate locations. A successful foreground write only
//! returns after the configured durability/metadata commit requirements have been met.

// Distributed object data plane: placement, immutable versions, erasure coding, encryption metadata, repair, and fragment RPC.
//! Cluster data plane: deterministic placement, replicated chunks, EC, encrypted metadata,
//! checksum validation, repair, and health-aware rebalancing.
use crate::erasure::{ErasureBackend, ErasureConfig, ErasureLayout, ErasureScheme, RepairFetch};
use crate::filesystem::FsMetadata;
use crate::pq::{LocalPqIdentity, RuntimeKeyring};
use crate::recovery::HealthMap;
use crate::storage::StorageKind;
use anyhow::{bail, Context, Result};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{post, put},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::RwLock,
};
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Ordered high-throughput transport policy. HTTPS remains the universal fallback.
/// Data-plane transport policy for fragment movement between Kagi peers.
///
/// The control plane remains authenticated independently of the selected data transport.
/// QUIC is optional at compile time and falls back to HTTPS when unavailable. RDMA fields
/// reserve the 0.39 policy surface; an advertised RDMA endpoint is not an availability claim.
pub struct DataTransportConfig {
    /// Prefer QUIC for eligible fragment traffic. Default: true.
    #[serde(default = "default_true")]
    pub prefer_quic: bool,
    /// Minimum payload size, in bytes, for QUIC preference. Default: 65,536.
    #[serde(default = "default_quic_min_bytes")]
    pub quic_min_bytes: usize,
    /// Maximum request/response body accepted by the framed transport. Default: 256 MiB.
    #[serde(default = "default_transport_frame_bytes")]
    pub max_frame_bytes: usize,
    /// Prefer RDMA when a functional backend is available. Default: true.
    #[serde(default = "default_true")]
    pub prefer_rdma: bool,
    /// Minimum payload size, in bytes, intended for RDMA selection. Default: 256 KiB.
    #[serde(default = "default_rdma_min_bytes")]
    pub rdma_min_bytes: usize,
}

impl Default for DataTransportConfig {
    fn default() -> Self {
        Self {
            prefer_quic: true,
            quic_min_bytes: default_quic_min_bytes(),
            max_frame_bytes: default_transport_frame_bytes(),
            prefer_rdma: true,
            rdma_min_bytes: default_rdma_min_bytes(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_quic_min_bytes() -> usize {
    64 * 1024
}

fn default_rdma_min_bytes() -> usize {
    256 * 1024
}

fn default_transport_frame_bytes() -> usize {
    256 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
// ---- Cluster topology and immutable object metadata ----------------------------
/// Runtime cluster topology, protection policy and transport configuration.
pub struct ClusterConfig {
    /// Stable cluster identifier shared by every member.
    pub id: String,
    /// Stable salt used by deterministic fragment placement.
    pub placement_salt: u64,
    /// Storage hosts eligible for placement.
    pub hosts: Vec<PeerHost>,
    /// Replica count for replication protection. Default: 3.
    #[serde(default = "default_replication")]
    pub replication: usize,
    /// Successful replica acknowledgements required for a write. Default: 2.
    #[serde(default = "default_quorum")]
    pub write_quorum: usize,
    /// Copies retained for each encoded fragment. Default: 1.
    #[serde(default = "one_usize")]
    pub chunk_replicas: usize,
    /// Optional erasure-coding policy; None retains replication-only protection.
    #[serde(default)]
    pub erasure: Option<ErasureConfig>,
    /// Base64 32-byte at-rest root key. Domain-separated subkeys protect metadata and fragments.
    #[serde(default)]
    pub metadata_key_b64: Option<String>,
    /// Optional stored verifier/hash representation of the cluster join key.
    #[serde(default)]
    pub join_key_hash_hex: Option<String>,
    /// Fragment data-plane selection and size thresholds.
    #[serde(default)]
    pub transport: DataTransportConfig,
}
/// Implements the default replication step and keeps its validation and state transitions visible at the call site.
fn default_replication() -> usize {
    3
}
/// Implements the default quorum step and keeps its validation and state transitions visible at the call site.
fn default_quorum() -> usize {
    2
}
/// Implements the one usize step and keeps its validation and state transitions visible at the call site.
fn one_usize() -> usize {
    1
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// One storage host and its advertised control/data-plane endpoints.
pub struct PeerHost {
    /// Stable host identifier used by placement and metadata.
    pub id: String,
    /// HTTPS control-plane and fallback data endpoint.
    pub endpoint: String,
    /// UDP QUIC socket advertised for bulk fragment traffic.
    #[serde(default)]
    pub quic_endpoint: Option<String>,
    /// Certificate name used when authenticating this peer's QUIC listener.
    #[serde(default)]
    pub quic_server_name: Option<String>,
    /// RDMA-CM address advertised when the optional direct-RDMA backend is enabled.
    #[serde(default)]
    pub rdma_endpoint: Option<String>,
    /// Optional site failure-domain label.
    #[serde(default)]
    pub site: Option<String>,
    /// Optional rack failure-domain label.
    #[serde(default)]
    pub rack: Option<String>,
    /// Physical/logical storage devices exposed by this host.
    pub disks: Vec<PeerDisk>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Placement and identity information for one host storage device.
pub struct PeerDisk {
    /// Stable disk identifier.
    pub id: String,
    /// Usable placement capacity in bytes.
    pub capacity_bytes: u64,
    /// Relative placement weight. Default: 1.0.
    #[serde(default = "one")]
    pub weight: f64,
    /// Optional Linux block-device path used for health, identity and queue controls.
    #[serde(default)]
    pub device_path: Option<String>,
    /// Optional expected serial number; a mismatch prevents safe admission.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// Optional expected WWN; a mismatch prevents safe admission.
    #[serde(default)]
    pub wwn: Option<String>,
    /// Expected storage media/transport class. Default: auto.
    #[serde(default)]
    pub storage_kind: StorageKind,
}
/// Implements the one step and keeps its validation and state transitions visible at the call site.
fn one() -> f64 {
    1.0
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentHeader {
    pub cluster: String,
    pub object_id: String,
    pub version: u64,
    pub fragment: u32,
    pub total_fragments: u32,
    pub key_position: u64,
    pub checksum: String,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentReplica {
    pub host: String,
    pub disk: String,
    #[serde(default)]
    pub checksum: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMetadata {
    pub chunk: u32,
    pub bytes: u64,
    pub checksum: String,
    pub replicas: Vec<FragmentReplica>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    pub algorithm: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    #[serde(default)]
    pub kdf_salt_b64: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    #[default]
    None,
    Governance,
    Compliance,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WormPolicy {
    #[serde(default)]
    pub mode: RetentionMode,
    #[serde(default)]
    pub retain_until_unix_ms: Option<u128>,
    #[serde(default)]
    pub legal_hold: bool,
}
impl WormPolicy {
    pub fn immutable(&self, now: u128) -> bool {
        self.legal_hold
            || matches!(
                self.mode,
                RetentionMode::Compliance | RetentionMode::Governance
            ) && self.retain_until_unix_ms.map(|x| x > now).unwrap_or(false)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedObjectMetadata {
    pub object_id: String,
    pub version: u64,
    pub bytes: u64,
    pub checksum: String,
    pub data_shards: u16,
    pub parity_shards: u16,
    #[serde(default)]
    pub erasure_scheme: ErasureScheme,
    #[serde(default)]
    pub repair_helpers: Option<u16>,
    #[serde(default)]
    pub sub_chunk_no: u32,
    pub chunks: Vec<ChunkMetadata>,
    #[serde(default)]
    pub worm: WormPolicy,
    #[serde(default)]
    pub fs: Option<FsMetadata>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the ObjectManifest path.
pub struct ObjectManifest {
    pub key: String,
    pub object_id: String,
    pub version: u64,
    pub bytes: u64,
    pub checksum: String,
    #[serde(default)]
    pub worm: WormPolicy,
    #[serde(default)]
    pub fs: Option<FsMetadata>,
    #[serde(default)]
    pub data_shards: u16,
    #[serde(default)]
    pub parity_shards: u16,
    #[serde(default)]
    pub erasure_scheme: ErasureScheme,
    #[serde(default)]
    pub repair_helpers: Option<u16>,
    #[serde(default)]
    pub sub_chunk_no: u32,
    #[serde(default)]
    pub fragments: Vec<FragmentLocation>,
    #[serde(default)]
    pub chunks: Vec<ChunkMetadata>,
    #[serde(default)]
    pub protected_metadata: Option<EncryptedMetadata>,
    pub committed_at_unix_ms: u128,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentLocation {
    pub fragment: u32,
    pub host: String,
    pub disk: String,
    #[serde(default)]
    pub checksum: Option<String>,
}
#[derive(Clone)]
pub struct ClusterState {
    pub cfg: Arc<ClusterConfig>,
    pub local_host: String,
    pub root: PathBuf,
    pub client: reqwest::Client,
    pub manifests: Arc<RwLock<BTreeMap<String, ObjectManifest>>>,
    pub erasure: Arc<dyn ErasureBackend>,
    pub pq_identity: Option<LocalPqIdentity>,
    pub pq_keys: RuntimeKeyring,
    /// Raw admission material is retained in-memory only so non-HTTP transports can
    /// carry the same admission proof as the existing internal HTTP client.
    pub join_key_b64: Option<String>,
    #[cfg(feature = "quic")]
    pub quic: Option<Arc<crate::quic_transport::Client>>,
}
/// Implements the hash64 step and keeps its validation and state transitions visible at the call site.
fn hash64(parts: &[&[u8]]) -> u64 {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap())
}
/// Implements the score step and keeps its validation and state transitions visible at the call site.
fn score(pos: u64, frag: u32, replica: u32, salt: u64, h: &PeerHost, d: &PeerDisk) -> f64 {
    let x = hash64(&[
        &pos.to_le_bytes(),
        &frag.to_le_bytes(),
        &replica.to_le_bytes(),
        &salt.to_le_bytes(),
        h.id.as_bytes(),
        d.id.as_bytes(),
    ]);
    let u = ((x as f64) + 1.0) / ((u64::MAX as f64) + 2.0);
    u.powf(1.0 / (d.capacity_bytes as f64 * d.weight).max(1.0))
}
/// Implements the placement health step and keeps its validation and state transitions visible at the call site.
async fn placement_health(
    cfg: &ClusterConfig,
    pos: u64,
    chunks: usize,
    reps: usize,
    health: Option<&HealthMap>,
) -> Result<Vec<Vec<FragmentLocation>>> {
    let mut all = Vec::new();
    let mut globally_used = BTreeSet::new();
    for f in 0..chunks {
        let mut rs = Vec::new();
        let mut used_hosts = BTreeSet::new();
        for r in 0..reps {
            let mut c = Vec::new();
            for h in &cfg.hosts {
                for d in &h.disks {
                    if health.map(|_| true).unwrap_or(true) {
                        if let Some(hm) = health {
                            if !hm.usable(h, &d.id).await {
                                continue;
                            }
                        }
                    }
                    c.push((
                        score(pos, f as u32, r as u32, cfg.placement_salt, h, d),
                        h,
                        d,
                    ));
                }
            }
            c.sort_by(|a, b| b.0.total_cmp(&a.0));
            let chosen = c
                .iter()
                .find(|(_, h, d)| {
                    !used_hosts.contains(&h.id)
                        && !globally_used.contains(&(h.id.clone(), d.id.clone()))
                })
                .or_else(|| {
                    c.iter()
                        .find(|(_, _, d)| !rs.iter().any(|x: &FragmentLocation| x.disk == d.id))
                })
                .or_else(|| c.first())
                .context("insufficient healthy placement targets")?;
            used_hosts.insert(chosen.1.id.clone());
            globally_used.insert((chosen.1.id.clone(), chosen.2.id.clone()));
            rs.push(FragmentLocation {
                fragment: f as u32,
                host: chosen.1.id.clone(),
                disk: chosen.2.id.clone(),
                checksum: None,
            });
        }
        all.push(rs);
    }
    Ok(all)
}
/// Implements the placement step and keeps its validation and state transitions visible at the call site.
pub fn placement(cfg: &ClusterConfig, pos: u64, n: usize) -> Result<Vec<FragmentLocation>> {
    // compatibility: one replica per chunk
    let rt = tokio::runtime::Handle::try_current();
    if rt.is_ok() {
        // synchronous callers cannot block current runtime; use equivalent unfiltered algorithm
        let mut out = Vec::new();
        for f in 0..n {
            let mut c = Vec::new();
            for h in &cfg.hosts {
                for d in &h.disks {
                    c.push((score(pos, f as u32, 0, cfg.placement_salt, h, d), h, d));
                }
            }
            c.sort_by(|a, b| b.0.total_cmp(&a.0));
            let x = c.first().context("no placement target")?;
            out.push(FragmentLocation {
                fragment: f as u32,
                host: x.1.id.clone(),
                disk: x.2.id.clone(),
                checksum: None,
            });
        }
        return Ok(out);
    }
    futures_free_placement(cfg, pos, n)
}
/// Implements the futures free placement step and keeps its validation and state transitions visible at the call site.
fn futures_free_placement(
    cfg: &ClusterConfig,
    pos: u64,
    n: usize,
) -> Result<Vec<FragmentLocation>> {
    let mut out = Vec::new();
    let mut used = BTreeSet::new();
    for f in 0..n {
        let mut c = Vec::new();
        for h in &cfg.hosts {
            for d in &h.disks {
                c.push((score(pos, f as u32, 0, cfg.placement_salt, h, d), h, d));
            }
        }
        c.sort_by(|a, b| b.0.total_cmp(&a.0));
        let x = c
            .iter()
            .find(|(_, h, d)| !used.contains(&(h.id.clone(), d.id.clone())))
            .or_else(|| c.first())
            .context("no placement target")?;
        used.insert((x.1.id.clone(), x.2.id.clone()));
        out.push(FragmentLocation {
            fragment: f as u32,
            host: x.1.id.clone(),
            disk: x.2.id.clone(),
            checksum: None,
        });
    }
    Ok(out)
}
/// Implements the object id step and keeps its validation and state transitions visible at the call site.
fn object_id(cluster: &str, key: &str, version: u64) -> String {
    let mut h = Hasher::new();
    h.update(cluster.as_bytes());
    h.update(key.as_bytes());
    h.update(&version.to_le_bytes());
    h.finalize().to_hex().to_string()
}
/// Implements the fragment path step and keeps its validation and state transitions visible at the call site.
pub fn fragment_path(root: &FsPath, disk: &str, obj: &str, ver: u64, frag: u32) -> PathBuf {
    root.join("disks")
        .join(disk)
        .join("fragments")
        .join(&obj[0..2])
        .join(&obj[2..4])
        .join(format!("{obj}.{ver}.{frag}.frag"))
}
/// Implements the manifest path step and keeps its validation and state transitions visible at the call site.
fn manifest_path(root: &FsPath, key: &str) -> PathBuf {
    root.join("manifests")
        .join(format!("{}.json", blake3::hash(key.as_bytes()).to_hex()))
}
/// Implements the metadata key step and keeps its validation and state transitions visible at the call site.
fn metadata_key(cfg: &ClusterConfig) -> Result<[u8; 32]> {
    let s = cfg
        .metadata_key_b64
        .as_ref()
        .context("cluster.metadata_key_b64 is required for encrypted metadata and fragments")?;
    let v = B64.decode(s).context("metadata_key_b64 must be base64")?;
    if v.len() != 32 {
        bail!("metadata_key_b64 must decode to exactly 32 bytes")
    }
    Ok(v.try_into().unwrap())
}
const PQ_METADATA_SUITE: &str = "XChaCha20-Poly1305-PQ128+BLAKE3-KDF+AAD+JSON+base64";
const FRAGMENT_ENVELOPE_MAGIC: &[u8; 8] = b"KAGIFR2\0";
const FRAGMENT_HEADER_BYTES: usize = 8 + 4 + 8 + 16;
const FRAGMENT_NONCE_PREFIX_BYTES: usize = 16;
const FRAGMENT_NONCE_BYTES: usize = 24;
const FRAGMENT_TAG_BYTES: usize = 16;
const FRAGMENT_AEAD_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct FragmentEnvelopeHeader {
    chunk_bytes: usize,
    plaintext_bytes: usize,
    nonce_prefix: [u8; FRAGMENT_NONCE_PREFIX_BYTES],
}

#[derive(Debug, Clone, Copy)]
struct FragmentAtRestRef<'a> {
    cfg: &'a ClusterConfig,
    path: &'a FsPath,
    object: &'a str,
    version: u64,
    fragment: u32,
    disk: &'a str,
}

fn fragment_at_rest_key(
    cfg: &ClusterConfig,
    object: &str,
    version: u64,
    fragment: u32,
    disk: &str,
) -> Result<[u8; 32]> {
    let root = metadata_key(cfg)?;
    let mut material = Vec::with_capacity(32 + object.len() + disk.len() + 24);
    material.extend_from_slice(&root);
    material.extend_from_slice(&(object.len() as u64).to_be_bytes());
    material.extend_from_slice(object.as_bytes());
    material.extend_from_slice(&version.to_be_bytes());
    material.extend_from_slice(&fragment.to_be_bytes());
    material.extend_from_slice(&(disk.len() as u64).to_be_bytes());
    material.extend_from_slice(disk.as_bytes());
    Ok(blake3::derive_key(
        "Kagi fragment at-rest chunked XChaCha20-Poly1305 key v2",
        &material,
    ))
}

fn encode_fragment_header(header: FragmentEnvelopeHeader) -> [u8; FRAGMENT_HEADER_BYTES] {
    let mut out = [0u8; FRAGMENT_HEADER_BYTES];
    out[..8].copy_from_slice(FRAGMENT_ENVELOPE_MAGIC);
    out[8..12].copy_from_slice(&(header.chunk_bytes as u32).to_be_bytes());
    out[12..20].copy_from_slice(&(header.plaintext_bytes as u64).to_be_bytes());
    out[20..36].copy_from_slice(&header.nonce_prefix);
    out
}

fn decode_fragment_header(bytes: &[u8]) -> Result<FragmentEnvelopeHeader> {
    if bytes.len() != FRAGMENT_HEADER_BYTES || &bytes[..8] != FRAGMENT_ENVELOPE_MAGIC {
        bail!("fragment is not a Kagi chunked encrypted-at-rest envelope")
    }
    let chunk_bytes = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let plaintext_bytes = u64::from_be_bytes(bytes[12..20].try_into().unwrap()) as usize;
    if chunk_bytes == 0 {
        bail!("invalid encrypted fragment chunk size")
    }
    let mut nonce_prefix = [0u8; FRAGMENT_NONCE_PREFIX_BYTES];
    nonce_prefix.copy_from_slice(&bytes[20..36]);
    Ok(FragmentEnvelopeHeader {
        chunk_bytes,
        plaintext_bytes,
        nonce_prefix,
    })
}

fn fragment_chunk_count(header: FragmentEnvelopeHeader) -> usize {
    header.plaintext_bytes.div_ceil(header.chunk_bytes).max(1)
}

fn fragment_chunk_plaintext_len(header: FragmentEnvelopeHeader, index: usize) -> Result<usize> {
    if index >= fragment_chunk_count(header) {
        bail!("encrypted fragment chunk index out of range")
    }
    let start = index
        .checked_mul(header.chunk_bytes)
        .context("encrypted fragment offset overflow")?;
    Ok(header
        .plaintext_bytes
        .saturating_sub(start)
        .min(header.chunk_bytes))
}

fn fragment_chunk_nonce(
    prefix: &[u8; FRAGMENT_NONCE_PREFIX_BYTES],
    index: usize,
) -> Result<[u8; FRAGMENT_NONCE_BYTES]> {
    let index = u64::try_from(index).context("encrypted fragment chunk index overflow")?;
    let mut nonce = [0u8; FRAGMENT_NONCE_BYTES];
    nonce[..FRAGMENT_NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[FRAGMENT_NONCE_PREFIX_BYTES..].copy_from_slice(&index.to_be_bytes());
    Ok(nonce)
}

fn fragment_chunk_aad(
    cfg: &ClusterConfig,
    object: &str,
    version: u64,
    fragment: u32,
    disk: &str,
    header_bytes: &[u8; FRAGMENT_HEADER_BYTES],
    index: usize,
) -> Result<Vec<u8>> {
    let mut aad =
        Vec::with_capacity(32 + cfg.id.len() + object.len() + disk.len() + header_bytes.len());
    aad.extend_from_slice(b"KAGI-FRAGMENT-CHUNK-AEAD-V2\\0");
    aad.extend_from_slice(&(cfg.id.len() as u64).to_be_bytes());
    aad.extend_from_slice(cfg.id.as_bytes());
    aad.extend_from_slice(&(object.len() as u64).to_be_bytes());
    aad.extend_from_slice(object.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&fragment.to_be_bytes());
    aad.extend_from_slice(&(disk.len() as u64).to_be_bytes());
    aad.extend_from_slice(disk.as_bytes());
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(
        &u64::try_from(index)
            .context("encrypted fragment chunk index overflow")?
            .to_be_bytes(),
    );
    Ok(aad)
}

fn protect_fragment_at_rest(
    cfg: &ClusterConfig,
    object: &str,
    version: u64,
    fragment: u32,
    disk: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = fragment_at_rest_key(cfg, object, version, fragment, disk)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce_prefix = [0u8; FRAGMENT_NONCE_PREFIX_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_prefix);
    let header = FragmentEnvelopeHeader {
        chunk_bytes: FRAGMENT_AEAD_CHUNK_BYTES,
        plaintext_bytes: plaintext.len(),
        nonce_prefix,
    };
    let header_bytes = encode_fragment_header(header);
    let chunks = fragment_chunk_count(header);
    let mut envelope =
        Vec::with_capacity(FRAGMENT_HEADER_BYTES + plaintext.len() + chunks * FRAGMENT_TAG_BYTES);
    envelope.extend_from_slice(&header_bytes);
    for index in 0..chunks {
        let start = index * header.chunk_bytes;
        let len = fragment_chunk_plaintext_len(header, index)?;
        let nonce = fragment_chunk_nonce(&header.nonce_prefix, index)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[start..start + len],
                    aad: &fragment_chunk_aad(
                        cfg,
                        object,
                        version,
                        fragment,
                        disk,
                        &header_bytes,
                        index,
                    )?,
                },
            )
            .map_err(|_| anyhow::anyhow!("fragment chunk encryption failed"))?;
        envelope.extend_from_slice(&ciphertext);
    }
    Ok(envelope)
}

fn unprotect_fragment_at_rest(
    cfg: &ClusterConfig,
    object: &str,
    version: u64,
    fragment: u32,
    disk: &str,
    envelope: &[u8],
) -> Result<Vec<u8>> {
    if envelope.len() < FRAGMENT_HEADER_BYTES + FRAGMENT_TAG_BYTES {
        bail!("truncated encrypted fragment")
    }
    let header_bytes: [u8; FRAGMENT_HEADER_BYTES] =
        envelope[..FRAGMENT_HEADER_BYTES].try_into().unwrap();
    let header = decode_fragment_header(&header_bytes)?;
    let chunks = fragment_chunk_count(header);
    let expected = FRAGMENT_HEADER_BYTES
        .checked_add(header.plaintext_bytes)
        .and_then(|value| value.checked_add(chunks * FRAGMENT_TAG_BYTES))
        .context("encrypted fragment length overflow")?;
    if envelope.len() != expected {
        bail!("encrypted fragment length mismatch")
    }
    let key = fragment_at_rest_key(cfg, object, version, fragment, disk)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut plaintext = Vec::with_capacity(header.plaintext_bytes);
    let mut offset = FRAGMENT_HEADER_BYTES;
    for index in 0..chunks {
        let plain_len = fragment_chunk_plaintext_len(header, index)?;
        let cipher_len = plain_len + FRAGMENT_TAG_BYTES;
        let nonce = fragment_chunk_nonce(&header.nonce_prefix, index)?;
        let chunk = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &envelope[offset..offset + cipher_len],
                    aad: &fragment_chunk_aad(
                        cfg,
                        object,
                        version,
                        fragment,
                        disk,
                        &header_bytes,
                        index,
                    )?,
                },
            )
            .map_err(|_| anyhow::anyhow!("fragment chunk authentication failed"))?;
        plaintext.extend_from_slice(&chunk);
        offset += cipher_len;
    }
    Ok(plaintext)
}

async fn write_fragment_at_rest(
    cfg: &ClusterConfig,
    path: &FsPath,
    object: &str,
    version: u64,
    fragment: u32,
    disk: &str,
    plaintext: &[u8],
) -> Result<()> {
    let envelope = protect_fragment_at_rest(cfg, object, version, fragment, disk, plaintext)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, envelope).await?;
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&temporary)
        .await?;
    file.sync_all().await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

async fn read_fragment_at_rest(
    cfg: &ClusterConfig,
    path: &FsPath,
    object: &str,
    version: u64,
    fragment: u32,
    disk: &str,
) -> Result<Vec<u8>> {
    let envelope = tokio::fs::read(path).await?;
    unprotect_fragment_at_rest(cfg, object, version, fragment, disk, &envelope)
}

async fn read_fragment_range_at_rest(
    fragment_ref: FragmentAtRestRef<'_>,
    range_start: usize,
    range_len: usize,
) -> Result<Vec<u8>> {
    let FragmentAtRestRef {
        cfg,
        path,
        object,
        version,
        fragment,
        disk,
    } = fragment_ref;
    let mut file = tokio::fs::File::open(path).await?;
    let mut raw_header = [0u8; FRAGMENT_HEADER_BYTES];
    file.read_exact(&mut raw_header).await?;
    let header = decode_fragment_header(&raw_header)?;
    let range_end = range_start
        .checked_add(range_len)
        .context("fragment range overflow")?;
    if range_end > header.plaintext_bytes {
        bail!("fragment plaintext range out of bounds")
    }
    if range_len == 0 {
        return Ok(Vec::new());
    }
    let chunks = fragment_chunk_count(header);
    let expected_file_len = FRAGMENT_HEADER_BYTES
        .checked_add(header.plaintext_bytes)
        .and_then(|value| value.checked_add(chunks * FRAGMENT_TAG_BYTES))
        .context("encrypted fragment length overflow")?;
    if file.metadata().await?.len() != expected_file_len as u64 {
        bail!("encrypted fragment length mismatch")
    }

    let key = fragment_at_rest_key(cfg, object, version, fragment, disk)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let first_chunk = range_start / header.chunk_bytes;
    let last_chunk = (range_end - 1) / header.chunk_bytes;
    let mut out = Vec::with_capacity(range_len);

    for index in first_chunk..=last_chunk {
        let plain_len = fragment_chunk_plaintext_len(header, index)?;
        let cipher_offset = FRAGMENT_HEADER_BYTES
            + index
                .checked_mul(header.chunk_bytes + FRAGMENT_TAG_BYTES)
                .context("encrypted fragment offset overflow")?;
        file.seek(std::io::SeekFrom::Start(cipher_offset as u64))
            .await?;
        let mut ciphertext = vec![0u8; plain_len + FRAGMENT_TAG_BYTES];
        file.read_exact(&mut ciphertext).await?;
        let nonce = fragment_chunk_nonce(&header.nonce_prefix, index)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &fragment_chunk_aad(
                        cfg,
                        object,
                        version,
                        fragment,
                        disk,
                        &raw_header,
                        index,
                    )?,
                },
            )
            .map_err(|_| anyhow::anyhow!("fragment chunk authentication failed"))?;
        let chunk_start = index * header.chunk_bytes;
        let copy_start = range_start.saturating_sub(chunk_start);
        let copy_end = plaintext.len().min(range_end - chunk_start);
        out.extend_from_slice(&plaintext[copy_start..copy_end]);
    }
    Ok(out)
}

async fn read_subchunks_at_rest(
    fragment_ref: FragmentAtRestRef<'_>,
    alpha: usize,
    indices: &[usize],
) -> Result<Vec<u8>> {
    let FragmentAtRestRef {
        cfg,
        path,
        object,
        version,
        fragment,
        disk,
    } = fragment_ref;
    if alpha == 0 || indices.is_empty() {
        bail!("subchunk request requires alpha>0 and at least one index")
    }
    let mut file = tokio::fs::File::open(path).await?;
    let mut raw_header = [0u8; FRAGMENT_HEADER_BYTES];
    file.read_exact(&mut raw_header).await?;
    let header = decode_fragment_header(&raw_header)?;
    if header.plaintext_bytes == 0 || !header.plaintext_bytes.is_multiple_of(alpha) {
        bail!(
            "fragment length {} is not divisible by alpha={alpha}",
            header.plaintext_bytes
        )
    }
    drop(file);
    let row_len = header.plaintext_bytes / alpha;
    let mut out = Vec::with_capacity(indices.len() * row_len);
    for &index in indices {
        if index >= alpha {
            bail!("subchunk index {index} out of range for alpha={alpha}")
        }
        out.extend_from_slice(
            &read_fragment_range_at_rest(fragment_ref, index * row_len, row_len).await?,
        );
    }
    Ok(out)
}
// ---- Protected metadata envelopes ----------------------------------------------
fn protect_metadata(cfg: &ClusterConfig, m: &ProtectedObjectMetadata) -> Result<EncryptedMetadata> {
    let root = metadata_key(cfg)?;
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    // 256-bit symmetric AEAD retains ~128-bit exhaustive-key security against an ideal Grover-capable adversary.
    // A fresh per-object subkey limits key reuse and blast radius; BLAKE3 derives it from the cluster root and random salt.
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(&root);
    material.extend_from_slice(&salt);
    let key = blake3::derive_key(
        "Kagi distributed storage metadata pq128 subkey v1",
        &material,
    );
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = serde_json::to_vec(m)?;
    let salt_b64 = B64.encode(salt);
    let aad = format!("{}:{}", PQ_METADATA_SUITE, salt_b64);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("metadata encryption failed"))?;
    Ok(EncryptedMetadata {
        algorithm: PQ_METADATA_SUITE.into(),
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ct),
        kdf_salt_b64: Some(salt_b64),
    })
}
/// Implements the unprotect metadata step and keeps its validation and state transitions visible at the call site.
pub fn unprotect_metadata(
    cfg: &ClusterConfig,
    e: &EncryptedMetadata,
) -> Result<ProtectedObjectMetadata> {
    let root = metadata_key(cfg)?;
    let nonce = B64.decode(&e.nonce_b64)?;
    let ct = B64.decode(&e.ciphertext_b64)?;
    if nonce.len() != 24 {
        bail!("invalid metadata nonce")
    };
    if e.algorithm == PQ_METADATA_SUITE {
        let salt = B64.decode(
            e.kdf_salt_b64
                .as_ref()
                .context("missing PQ metadata KDF salt")?,
        )?;
        if salt.len() != 32 {
            bail!("invalid PQ metadata KDF salt")
        };
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&root);
        material.extend_from_slice(&salt);
        let key = blake3::derive_key(
            "Kagi distributed storage metadata pq128 subkey v1",
            &material,
        );
        let cipher = XChaCha20Poly1305::new((&key).into());
        // object id/version are authenticated inside the ciphertext; decrypt once without external identity context using suite+salt AAD would not bind manifest identity.
        // Bind the immutable envelope salt/suite; the decoded object_id/version are subsequently cross-checked by callers against the manifest.
        let aad = format!("{}:{}", PQ_METADATA_SUITE, e.kdf_salt_b64.as_ref().unwrap());
        // Compatibility with v15 writer AAD is handled below by using envelope AAD for new writes.
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("metadata authentication failed"))?;
        return Ok(serde_json::from_slice(&pt)?);
    }
    // v14 and earlier envelope compatibility.
    let cipher = XChaCha20Poly1305::new((&root).into());
    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| anyhow::anyhow!("metadata authentication failed"))?;
    Ok(serde_json::from_slice(&pt)?)
}
// ---- Authenticated fragment transport ------------------------------------------
#[cfg(feature = "quic")]
async fn quic_request(
    st: &ClusterState,
    peer: &PeerHost,
    method: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, String)],
) -> Result<Option<Vec<u8>>> {
    if !st.cfg.transport.prefer_quic {
        return Ok(None);
    }
    let (Some(client), Some(endpoint)) = (st.quic.as_ref(), peer.quic_endpoint.as_deref()) else {
        return Ok(None);
    };
    let Ok(address) = endpoint.parse::<std::net::SocketAddr>() else {
        return Ok(None);
    };
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(id, method, path, body)?;
    let mut headers = BTreeMap::new();
    for (name, value) in auth {
        headers.insert(name.to_string(), value);
    }
    if let Some(join_key) = st.join_key_b64.as_ref() {
        headers.insert("x-kagi-join-key".into(), join_key.clone());
    }
    for (name, value) in extra_headers {
        headers.insert((*name).to_string(), value.clone());
    }

    let meta = crate::quic_transport::RequestMeta {
        method: method.into(),
        path: path.into(),
        headers,
    };
    let server_name = peer.quic_server_name.as_deref().unwrap_or(&peer.id);
    match client.request(address, server_name, meta, body).await {
        Ok(response) => Ok(Some(response.ensure_success()?)),
        // QUIC is an acceleration path. A transport/connectivity failure falls back to
        // HTTPS; an authenticated peer application error above does not.
        Err(_) => Ok(None),
    }
}

#[cfg(feature = "quic")]
fn manifest_fragment_bytes(manifest: &ObjectManifest, fragment: u32) -> u64 {
    normalize_chunks(manifest)
        .iter()
        .find(|chunk| chunk.chunk == fragment)
        .map(|chunk| chunk.bytes)
        .unwrap_or(0)
}

async fn rpc_store(
    st: &ClusterState,
    loc: &FragmentLocation,
    h: &FragmentHeader,
    data: &[u8],
) -> Result<()> {
    if loc.host == st.local_host {
        let p = fragment_path(&st.root, &loc.disk, &h.object_id, h.version, h.fragment);
        write_fragment_at_rest(
            &st.cfg,
            &p,
            &h.object_id,
            h.version,
            h.fragment,
            &loc.disk,
            data,
        )
        .await?;
        return Ok(());
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}",
        h.object_id, h.version, h.fragment, loc.disk
    );
    #[cfg(feature = "quic")]
    if data.len() >= st.cfg.transport.quic_min_bytes {
        let extra = [
            ("x-kagi-cluster", h.cluster.clone()),
            ("x-kagi-checksum", h.checksum.clone()),
            ("x-kagi-position", h.key_position.to_string()),
        ];
        if quic_request(st, peer, "PUT", &path, data, &extra)
            .await?
            .is_some()
        {
            return Ok(());
        }
    }
    let url = format!(
        "{}/internal/v1/fragment/{}/{}/{}/{}",
        peer.endpoint.trim_end_matches('/'),
        h.object_id,
        h.version,
        h.fragment,
        loc.disk
    );
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(id, "PUT", &path, data)?;
    let b = st
        .client
        .put(url)
        .header("x-kagi-cluster", &h.cluster)
        .header("x-kagi-checksum", &h.checksum)
        .header("x-kagi-position", h.key_position.to_string())
        .body(data.to_vec());
    let r = crate::pq::apply_headers(b, auth).send().await?;
    if !r.status().is_success() {
        bail!("peer {} returned {}", peer.id, r.status())
    }
    Ok(())
}
/// Implements the rpc get step and keeps its validation and state transitions visible at the call site.
async fn rpc_get(st: &ClusterState, loc: &FragmentLocation, m: &ObjectManifest) -> Result<Vec<u8>> {
    if loc.host == st.local_host {
        let path = fragment_path(&st.root, &loc.disk, &m.object_id, m.version, loc.fragment);
        return read_fragment_at_rest(
            &st.cfg,
            &path,
            &m.object_id,
            m.version,
            loc.fragment,
            &loc.disk,
        )
        .await;
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}",
        m.object_id, m.version, loc.fragment, loc.disk
    );
    #[cfg(feature = "quic")]
    if manifest_fragment_bytes(m, loc.fragment) as usize >= st.cfg.transport.quic_min_bytes {
        if let Some(body) = quic_request(st, peer, "GET", &path, &[], &[]).await? {
            return Ok(body);
        }
    }
    let url = format!(
        "{}/internal/v1/fragment/{}/{}/{}/{}",
        peer.endpoint.trim_end_matches('/'),
        m.object_id,
        m.version,
        loc.fragment,
        loc.disk
    );
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(id, "GET", &path, &[])?;
    let r = crate::pq::apply_headers(st.client.get(url), auth)
        .send()
        .await?;
    if !r.status().is_success() {
        bail!("peer read {}", r.status())
    }
    Ok(r.bytes().await?.to_vec())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the SubchunkRequest path.
struct SubchunkRequest {
    alpha: usize,
    indices: Vec<usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the ProjectionRequest path.
struct ProjectionRequest {
    rows: usize,
    coeff_b64: String,
}
/// Implements the read subchunks step and keeps its validation and state transitions visible at the call site.
/// Read only the CLAY subchunks named by the exact-repair plan. Remote peers
/// receive a signed request and perform positioned reads, so unused subchunks
/// never cross either the disk or network repair path.
async fn rpc_get_subchunks(
    st: &ClusterState,
    loc: &FragmentLocation,
    m: &ObjectManifest,
    alpha: usize,
    indices: &[usize],
) -> Result<Vec<u8>> {
    if loc.host == st.local_host {
        let path = fragment_path(&st.root, &loc.disk, &m.object_id, m.version, loc.fragment);
        return read_subchunks_at_rest(
            FragmentAtRestRef {
                cfg: &st.cfg,
                path: &path,
                object: &m.object_id,
                version: m.version,
                fragment: loc.fragment,
                disk: &loc.disk,
            },
            alpha,
            indices,
        )
        .await;
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}/subchunks",
        m.object_id, m.version, loc.fragment, loc.disk
    );
    let url = format!("{}{}", peer.endpoint.trim_end_matches('/'), path);
    let body = serde_json::to_vec(&SubchunkRequest {
        alpha,
        indices: indices.to_vec(),
    })?;
    #[cfg(feature = "quic")]
    if let Some(output) = quic_request(st, peer, "POST", &path, &body, &[]).await? {
        return Ok(output);
    }
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(id, "POST", &path, &body)?;
    let req = st
        .client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body);
    let r = crate::pq::apply_headers(req, auth).send().await?;
    if !r.status().is_success() {
        bail!("peer CLAY subchunk read {}", r.status())
    }
    Ok(r.bytes().await?.to_vec())
}
/// Ask an MSR helper to compute its repair projection locally. With CUDA
/// enabled the helper's GF matrix projection is dispatched through the same
/// GPU engine used for encoding, so only beta rows traverse the network.
async fn rpc_project(
    st: &ClusterState,
    loc: &FragmentLocation,
    m: &ObjectManifest,
    rows: usize,
    coeff: &[u8],
) -> Result<Vec<u8>> {
    if rows == 0 || coeff.is_empty() || !coeff.len().is_multiple_of(rows) {
        bail!("invalid projection matrix")
    }
    if loc.host == st.local_host {
        let path = fragment_path(&st.root, &loc.disk, &m.object_id, m.version, loc.fragment);
        let v = read_fragment_at_rest(
            &st.cfg,
            &path,
            &m.object_id,
            m.version,
            loc.fragment,
            &loc.disk,
        )
        .await?;
        if !v.len().is_multiple_of(rows) {
            bail!("fragment length is not divisible by projection rows")
        }
        return st
            .erasure
            .linear_transform(&v, rows, coeff, coeff.len() / rows, v.len() / rows)
            .await;
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}/project",
        m.object_id, m.version, loc.fragment, loc.disk
    );
    let url = format!("{}{}", peer.endpoint.trim_end_matches('/'), path);
    let body = serde_json::to_vec(&ProjectionRequest {
        rows,
        coeff_b64: B64.encode(coeff),
    })?;
    #[cfg(feature = "quic")]
    if let Some(output) = quic_request(st, peer, "POST", &path, &body, &[]).await? {
        return Ok(output);
    }
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(id, "POST", &path, &body)?;
    let req = st
        .client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body);
    let r = crate::pq::apply_headers(req, auth).send().await?;
    if !r.status().is_success() {
        bail!("peer MSR projection {}", r.status())
    }
    Ok(r.bytes().await?.to_vec())
}
// ---- Object create/read/repair/scrub operations --------------------------------
pub async fn put_object(st: &ClusterState, key: &str, data: &[u8]) -> Result<ObjectManifest> {
    put_object_inner(st, key, data, None, WormPolicy::default(), None).await
}
/// Implements the put filesystem object step and keeps its validation and state transitions visible at the call site.
pub async fn put_filesystem_object(
    st: &ClusterState,
    key: &str,
    data: &[u8],
    health: Option<&HealthMap>,
    worm: WormPolicy,
    fs: FsMetadata,
) -> Result<ObjectManifest> {
    put_object_inner(st, key, data, health, worm, Some(fs)).await
}
/// Implements the put object inner step and keeps its validation and state transitions visible at the call site.
async fn put_object_inner(
    st: &ClusterState,
    key: &str,
    data: &[u8],
    health: Option<&HealthMap>,
    worm: WormPolicy,
    fs: Option<FsMetadata>,
) -> Result<ObjectManifest> {
    let pos = hash64(&[st.cfg.id.as_bytes(), b"\0", key.as_bytes()]);
    let version = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let oid = object_id(&st.cfg.id, key, version);
    let checksum = blake3::hash(data).to_hex().to_string();
    let ec = st.cfg.erasure.clone();
    let (payloads, k, p, scheme, repair_helpers, sub_chunk_no) = if let Some(c) = &ec {
        let e = st
            .erasure
            .encode(data, c.data_shards, c.parity_shards)
            .await?;
        (
            e.shards,
            e.data_shards as usize,
            e.parity_shards as usize,
            e.scheme,
            e.repair_helpers,
            e.sub_chunk_no,
        )
    } else {
        (
            (0..st.cfg.replication).map(|_| data.to_vec()).collect(),
            1,
            0,
            ErasureScheme::ReedSolomon,
            None,
            0,
        )
    };
    let desired = placement_health(
        &st.cfg,
        pos,
        payloads.len(),
        st.cfg.chunk_replicas.max(1),
        health,
    )
    .await?;
    let required = if ec.is_some() { k } else { st.cfg.write_quorum };
    let mut chunks = Vec::new();
    let mut flat = Vec::new();
    let mut successful_chunks = 0;
    for (i, payload) in payloads.iter().enumerate() {
        let sum = blake3::hash(payload).to_hex().to_string();
        let mut replicas = Vec::new();
        for loc in &desired[i] {
            let hdr = FragmentHeader {
                cluster: st.cfg.id.clone(),
                object_id: oid.clone(),
                version,
                fragment: i as u32,
                total_fragments: payloads.len() as u32,
                key_position: pos,
                checksum: sum.clone(),
                bytes: payload.len() as u64,
            };
            if rpc_store(st, loc, &hdr, payload).await.is_ok() {
                replicas.push(FragmentReplica {
                    host: loc.host.clone(),
                    disk: loc.disk.clone(),
                    checksum: Some(sum.clone()),
                });
                flat.push(FragmentLocation {
                    fragment: i as u32,
                    host: loc.host.clone(),
                    disk: loc.disk.clone(),
                    checksum: Some(sum.clone()),
                });
            }
        }
        if !replicas.is_empty() {
            successful_chunks += 1
        }
        chunks.push(ChunkMetadata {
            chunk: i as u32,
            bytes: payload.len() as u64,
            checksum: sum,
            replicas,
        });
    }
    if successful_chunks < required {
        bail!("write quorum not reached: {successful_chunks}/{required}")
    }
    let protected = protect_metadata(
        &st.cfg,
        &ProtectedObjectMetadata {
            object_id: oid.clone(),
            version,
            bytes: data.len() as u64,
            checksum: checksum.clone(),
            data_shards: if ec.is_some() { k as u16 } else { 0 },
            parity_shards: p as u16,
            erasure_scheme: scheme,
            repair_helpers,
            sub_chunk_no,
            chunks: chunks.clone(),
            worm: worm.clone(),
            fs: fs.clone(),
        },
    )?;
    let m = ObjectManifest {
        key: key.into(),
        object_id: oid,
        version,
        bytes: data.len() as u64,
        checksum,
        worm,
        fs,
        data_shards: if ec.is_some() { k as u16 } else { 0 },
        parity_shards: p as u16,
        erasure_scheme: scheme,
        repair_helpers,
        sub_chunk_no,
        fragments: flat,
        chunks,
        protected_metadata: Some(protected),
        committed_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    };
    let mp = manifest_path(&st.root, key);
    tokio::fs::create_dir_all(mp.parent().unwrap()).await?;
    tokio::fs::write(&mp, serde_json::to_vec_pretty(&m)?).await?;
    st.manifests.write().await.insert(key.into(), m.clone());
    Ok(m)
}
/// Implements the normalize chunks step and keeps its validation and state transitions visible at the call site.
pub fn normalize_chunks(m: &ObjectManifest) -> Vec<ChunkMetadata> {
    if !m.chunks.is_empty() {
        return m.chunks.clone();
    }
    let mut x: BTreeMap<u32, ChunkMetadata> = BTreeMap::new();
    for f in &m.fragments {
        let e = x.entry(f.fragment).or_insert(ChunkMetadata {
            chunk: f.fragment,
            bytes: 0,
            checksum: f.checksum.clone().unwrap_or_default(),
            replicas: Vec::new(),
        });
        e.replicas.push(FragmentReplica {
            host: f.host.clone(),
            disk: f.disk.clone(),
            checksum: f.checksum.clone(),
        });
    }
    x.into_values().collect()
}
/// Implements the get object step and keeps its validation and state transitions visible at the call site.
pub async fn get_object(st: &ClusterState, key: &str) -> Result<Vec<u8>> {
    let m = if let Some(x) = st.manifests.read().await.get(key).cloned() {
        x
    } else {
        serde_json::from_slice(&tokio::fs::read(manifest_path(&st.root, key)).await?)?
    };
    if let Some(env) = &m.protected_metadata {
        let protected = unprotect_metadata(&st.cfg, env)?;
        if protected.object_id != m.object_id
            || protected.version != m.version
            || protected.bytes != m.bytes
            || protected.checksum != m.checksum
        {
            bail!("protected object metadata does not match manifest identity")
        }
    }
    let chunks = normalize_chunks(&m);
    if m.data_shards == 0 {
        for c in &chunks {
            for r in &c.replicas {
                let loc = FragmentLocation {
                    fragment: c.chunk,
                    host: r.host.clone(),
                    disk: r.disk.clone(),
                    checksum: r.checksum.clone(),
                };
                if let Ok(v) = rpc_get(st, &loc, &m).await {
                    if blake3::hash(&v).to_hex().to_string() == m.checksum {
                        return Ok(v);
                    }
                }
            }
        }
        bail!("no readable checksum-valid replica")
    }
    let k = m.data_shards as usize;
    let p = m.parity_shards as usize;
    let mut shards = vec![None; k + p];
    for c in &chunks {
        for r in &c.replicas {
            let loc = FragmentLocation {
                fragment: c.chunk,
                host: r.host.clone(),
                disk: r.disk.clone(),
                checksum: r.checksum.clone(),
            };
            if let Ok(v) = rpc_get(st, &loc, &m).await {
                if blake3::hash(&v).to_hex().to_string() == c.checksum {
                    shards[c.chunk as usize] = Some(v);
                    break;
                }
            }
        }
    }
    if shards.iter().filter(|x| x.is_some()).count() < k {
        bail!("insufficient EC shards for reconstruction")
    };
    let layout = ErasureLayout {
        scheme: m.erasure_scheme,
        data_shards: k,
        parity_shards: p,
        repair_helpers: m.repair_helpers.map(|x| x as usize),
    };
    let out = st
        .erasure
        .reconstruct_layout(&mut shards, m.bytes, &layout)
        .await?;
    if blake3::hash(&out).to_hex().to_string() != m.checksum {
        bail!("reconstructed object checksum mismatch")
    }
    Ok(out)
}
/// Implements the get object version step and keeps its validation and state transitions visible at the call site.
pub async fn get_object_version(st: &ClusterState, m: &ObjectManifest) -> Result<Vec<u8>> {
    st.manifests.write().await.insert(m.key.clone(), m.clone());
    get_object(st, &m.key).await
}
/// Implements the repair object step and keeps its validation and state transitions visible at the call site.
pub async fn repair_object(st: &ClusterState, key: &str) -> Result<ObjectManifest> {
    repair_object_inner(st, key, None).await
}
/// Implements the repair object with health step and keeps its validation and state transitions visible at the call site.
pub async fn repair_object_with_health(
    st: &ClusterState,
    key: &str,
    health: &HealthMap,
) -> Result<ObjectManifest> {
    repair_object_inner(st, key, Some(health)).await
}
/// Return whether a recorded replica is eligible to participate in repair.
/// When no health map is supplied all recorded replicas are candidates; actual
/// I/O errors are still handled by trying another replica of the same chunk.
async fn replica_usable(
    st: &ClusterState,
    r: &FragmentReplica,
    health: Option<&HealthMap>,
) -> bool {
    let Some(hm) = health else { return true };
    let Some(host) = st.cfg.hosts.iter().find(|h| h.id == r.host) else {
        return false;
    };
    hm.usable(host, &r.disk).await
}
/// Implements the read valid chunk step and keeps its validation and state transitions visible at the call site.
async fn read_valid_chunk(
    st: &ClusterState,
    m: &ObjectManifest,
    c: &ChunkMetadata,
    health: Option<&HealthMap>,
) -> Result<Vec<u8>> {
    for r in &c.replicas {
        if !replica_usable(st, r, health).await {
            continue;
        }
        let loc = FragmentLocation {
            fragment: c.chunk,
            host: r.host.clone(),
            disk: r.disk.clone(),
            checksum: r.checksum.clone(),
        };
        if let Ok(v) = rpc_get(st, &loc, m).await {
            if blake3::hash(&v).to_hex().to_string() == c.checksum {
                return Ok(v);
            }
        }
    }
    bail!("no checksum-valid replica for chunk {}", c.chunk)
}
/// Attempt a bandwidth-optimal single-chunk exact repair.  The codec produces
/// the helper request plan; the data plane executes those requests against one
/// healthy replica of each helper chunk and validates the recovered immutable
/// chunk against the manifest checksum before it can be used.
async fn try_exact_repair(
    st: &ClusterState,
    m: &ObjectManifest,
    health: Option<&HealthMap>,
) -> Result<Option<(usize, Vec<u8>)>> {
    if m.data_shards == 0 || !matches!(m.erasure_scheme, ErasureScheme::Msr | ErasureScheme::Clay) {
        return Ok(None);
    }
    let n = m.data_shards as usize + m.parity_shards as usize;
    let chunks = normalize_chunks(m);
    if chunks.len() != n {
        return Ok(None);
    }
    let mut available = Vec::new();
    let mut missing = Vec::new();
    for i in 0..n {
        let Some(c) = chunks.iter().find(|c| c.chunk as usize == i) else {
            return Ok(None);
        };
        let mut any = false;
        for r in &c.replicas {
            if replica_usable(st, r, health).await {
                any = true;
                break;
            }
        }
        if any {
            available.push(i)
        } else {
            missing.push(i)
        }
    }
    if missing.len() != 1 {
        return Ok(None);
    }
    let lost = missing[0];
    let c = chunks
        .iter()
        .find(|c| c.chunk as usize == lost)
        .context("lost chunk metadata missing")?;
    let chunk_len = c.bytes as usize;
    if chunk_len == 0 || c.checksum.is_empty() {
        return Ok(None);
    }
    let layout = ErasureLayout {
        scheme: m.erasure_scheme,
        data_shards: m.data_shards as usize,
        parity_shards: m.parity_shards as usize,
        repair_helpers: m.repair_helpers.map(|x| x as usize),
    };
    let Some(plan) = st
        .erasure
        .exact_repair_plan(&available, lost, chunk_len, &layout)?
    else {
        return Ok(None);
    };
    let mut helper_payloads = Vec::with_capacity(plan.fetches.len());
    for fetch in &plan.fetches {
        let helper = chunks
            .iter()
            .find(|c| c.chunk as usize == fetch.shard())
            .context("repair helper metadata missing")?;
        let mut result = None;
        for r in &helper.replicas {
            if !replica_usable(st, r, health).await {
                continue;
            }
            let loc = FragmentLocation {
                fragment: helper.chunk,
                host: r.host.clone(),
                disk: r.disk.clone(),
                checksum: r.checksum.clone(),
            };
            let got = match fetch {
                RepairFetch::SubChunks { alpha, indices, .. } => {
                    rpc_get_subchunks(st, &loc, m, *alpha, indices).await
                }
                RepairFetch::Projection { rows, coeff, .. } => {
                    rpc_project(st, &loc, m, *rows, coeff).await
                }
            };
            if let Ok(v) = got {
                result = Some(v);
                break;
            }
        }
        helper_payloads.push(result.with_context(|| {
            format!(
                "all replicas failed for exact-repair helper chunk {}",
                fetch.shard()
            )
        })?);
    }
    let repaired = st
        .erasure
        .apply_exact_repair(&plan, &helper_payloads)
        .await?;
    if blake3::hash(&repaired).to_hex().to_string() != c.checksum {
        bail!("exact repair checksum mismatch for chunk {lost}")
    }
    Ok(Some((lost, repaired)))
}
/// Rebuild placement without gratuitously decoding and re-encoding every EC
/// object. Existing healthy chunks are copied as encoded chunks; a single lost
/// CLAY/MSR chunk takes the exact-repair path. Multiple losses fall back to
/// full object reconstruction so normal MDS erasure tolerance remains intact.
async fn repair_object_inner(
    st: &ClusterState,
    key: &str,
    health: Option<&HealthMap>,
) -> Result<ObjectManifest> {
    let mut old = st
        .manifests
        .read()
        .await
        .get(key)
        .cloned()
        .context("manifest unavailable")?;
    let pos = hash64(&[st.cfg.id.as_bytes(), b"\0", key.as_bytes()]);
    let old_chunks = normalize_chunks(&old);
    let total = if old.data_shards > 0 {
        old.data_shards as usize + old.parity_shards as usize
    } else {
        st.cfg.replication
    };
    let exact = try_exact_repair(st, &old, health).await.ok().flatten();
    let mut payload_cache: Vec<Option<Vec<u8>>> = vec![None; total];
    if let Some((lost, payload)) = exact {
        payload_cache[lost] = Some(payload)
    }
    // If more than one logical EC chunk is unavailable, or the codec has no exact
    // repair plan, reconstruct once and re-encode as the conservative fallback.
    if old.data_shards > 0 {
        let mut unavailable = 0usize;
        for i in 0..total {
            let Some(c) = old_chunks.iter().find(|c| c.chunk as usize == i) else {
                unavailable += 1;
                continue;
            };
            let mut any = false;
            for r in &c.replicas {
                if replica_usable(st, r, health).await {
                    any = true;
                    break;
                }
            }
            if !any {
                unavailable += 1
            }
        }
        if unavailable > 0 && payload_cache.iter().all(|x| x.is_none()) {
            let data = get_object(st, key).await?;
            let layout = ErasureLayout {
                scheme: old.erasure_scheme,
                data_shards: old.data_shards as usize,
                parity_shards: old.parity_shards as usize,
                repair_helpers: old.repair_helpers.map(|x| x as usize),
            };
            payload_cache = st
                .erasure
                .encode_layout(&data, &layout)
                .await?
                .shards
                .into_iter()
                .map(Some)
                .collect();
        }
    } else {
        let data = get_object(st, key).await?;
        payload_cache = (0..total).map(|_| Some(data.clone())).collect();
    }
    let desired =
        placement_health(&st.cfg, pos, total, st.cfg.chunk_replicas.max(1), health).await?;
    let mut chunks = Vec::with_capacity(total);
    let mut flat = Vec::new();
    for i in 0..total {
        let oldc = old_chunks.iter().find(|c| c.chunk as usize == i).cloned();
        let mut checksum = oldc
            .as_ref()
            .map(|c| c.checksum.clone())
            .unwrap_or_default();
        let mut bytes = oldc.as_ref().map(|c| c.bytes).unwrap_or(0);
        let mut replicas = Vec::new();
        for target in &desired[i] {
            let existing = oldc.as_ref().and_then(|c| {
                c.replicas
                    .iter()
                    .find(|r| r.host == target.host && r.disk == target.disk)
            });
            let keep = if let Some(r) = existing {
                replica_usable(st, r, health).await
            } else {
                false
            };
            let ok = if keep {
                true
            } else {
                if payload_cache[i].is_none() {
                    let c = oldc
                        .as_ref()
                        .with_context(|| format!("chunk {i} metadata unavailable for rebalance"))?;
                    payload_cache[i] = Some(read_valid_chunk(st, &old, c, health).await?);
                }
                let payload = payload_cache[i].as_ref().unwrap();
                if checksum.is_empty() {
                    checksum = blake3::hash(payload).to_hex().to_string()
                }
                bytes = payload.len() as u64;
                let hdr = FragmentHeader {
                    cluster: st.cfg.id.clone(),
                    object_id: old.object_id.clone(),
                    version: old.version,
                    fragment: i as u32,
                    total_fragments: total as u32,
                    key_position: pos,
                    checksum: checksum.clone(),
                    bytes,
                };
                rpc_store(st, target, &hdr, payload).await.is_ok()
            };
            if ok {
                replicas.push(FragmentReplica {
                    host: target.host.clone(),
                    disk: target.disk.clone(),
                    checksum: Some(checksum.clone()),
                });
                flat.push(FragmentLocation {
                    fragment: i as u32,
                    host: target.host.clone(),
                    disk: target.disk.clone(),
                    checksum: Some(checksum.clone()),
                });
            }
        }
        if replicas.is_empty() {
            bail!("repair left chunk {i} without a replica")
        }
        chunks.push(ChunkMetadata {
            chunk: i as u32,
            bytes,
            checksum,
            replicas,
        });
    }
    old.fragments = flat;
    old.chunks = chunks.clone();
    old.protected_metadata = Some(protect_metadata(
        &st.cfg,
        &ProtectedObjectMetadata {
            object_id: old.object_id.clone(),
            version: old.version,
            bytes: old.bytes,
            checksum: old.checksum.clone(),
            data_shards: old.data_shards,
            parity_shards: old.parity_shards,
            erasure_scheme: old.erasure_scheme,
            repair_helpers: old.repair_helpers,
            sub_chunk_no: old.sub_chunk_no,
            chunks,
            worm: old.worm.clone(),
            fs: old.fs.clone(),
        },
    )?);
    st.manifests.write().await.insert(key.into(), old.clone());
    tokio::fs::write(
        manifest_path(&st.root, key),
        serde_json::to_vec_pretty(&old)?,
    )
    .await?;
    Ok(old)
}
/// Implements the scrub object step and keeps its validation and state transitions visible at the call site.
pub async fn scrub_object(st: &ClusterState, key: &str) -> Result<BTreeMap<String, bool>> {
    let m = st
        .manifests
        .read()
        .await
        .get(key)
        .cloned()
        .context("manifest unavailable")?;
    let mut out = BTreeMap::new();
    for c in normalize_chunks(&m) {
        for r in c.replicas {
            let loc = FragmentLocation {
                fragment: c.chunk,
                host: r.host.clone(),
                disk: r.disk.clone(),
                checksum: r.checksum,
            };
            let good = rpc_get(st, &loc, &m)
                .await
                .map(|v| blake3::hash(&v).to_hex().to_string() == c.checksum)
                .unwrap_or(false);
            out.insert(format!("chunk{}:{}/{}", c.chunk, r.host, r.disk), good);
        }
    }
    Ok(out)
}
// ---- Internal fragment service and authorization -------------------------------
fn join_authorized(cfg: &ClusterConfig, headers: &axum::http::HeaderMap) -> bool {
    let Some(want) = cfg.join_key_hash_hex.as_deref() else {
        return false;
    };
    let Some(raw) = headers
        .get("x-kagi-join-key")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(bytes) = B64.decode(raw) else {
        return false;
    };
    blake3::hash(&bytes).to_hex().to_string() == want
}

/// Delete one replica after a successful rebalance. Local deletion tolerates
/// already-removed files; remote deletion retains the same ML-DSA/join-key
/// authorization as every other internal fragment operation.
async fn rpc_delete_replica(
    st: &ClusterState,
    loc: &FragmentLocation,
    manifest: &ObjectManifest,
) -> Result<()> {
    if loc.host == st.local_host {
        let path = fragment_path(
            &st.root,
            &loc.disk,
            &manifest.object_id,
            manifest.version,
            loc.fragment,
        );
        match tokio::fs::remove_file(path).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }

    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|host| host.id == loc.host)
        .context("peer missing")?;
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}",
        manifest.object_id, manifest.version, loc.fragment, loc.disk
    );

    #[cfg(feature = "quic")]
    if quic_request(st, peer, "DELETE", &path, &[], &[])
        .await?
        .is_some()
    {
        return Ok(());
    }

    let url = format!("{}{}", peer.endpoint.trim_end_matches('/'), path);
    let identity = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(identity, "DELETE", &path, &[])?;
    let response = crate::pq::apply_headers(st.client.delete(url), auth)
        .send()
        .await?;
    if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
        bail!("peer delete {}", response.status());
    }
    Ok(())
}

/// Remove obsolete physical replicas only after the replacement manifest has
/// been committed. This preserves rebalance safety while allowing retries to be
/// idempotent.
pub async fn cleanup_rebalanced_replicas(
    st: &ClusterState,
    old: &ObjectManifest,
    new: &ObjectManifest,
) -> Result<()> {
    let keep: BTreeSet<_> = new
        .fragments
        .iter()
        .map(|location| {
            (
                location.fragment,
                location.host.clone(),
                location.disk.clone(),
            )
        })
        .collect();
    for location in &old.fragments {
        if !keep.contains(&(
            location.fragment,
            location.host.clone(),
            location.disk.clone(),
        )) {
            rpc_delete_replica(st, location, old).await?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct InternalFragmentResult {
    status: StatusCode,
    body: Vec<u8>,
}

impl InternalFragmentResult {
    fn new(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    fn empty(status: StatusCode) -> Self {
        Self {
            status,
            body: Vec::new(),
        }
    }

    fn into_response(self) -> axum::response::Response {
        (self.status, self.body).into_response()
    }
}

fn fragment_route(path: &str) -> Option<(String, u64, u32, String, Option<String>)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    if parts.len() < 7 || parts[0] != "internal" || parts[1] != "v1" || parts[2] != "fragment" {
        return None;
    }
    let version = parts[4].parse().ok()?;
    let fragment = parts[5].parse().ok()?;
    let operation = parts.get(7).map(|value| (*value).to_string());
    if parts.len() > 8 {
        return None;
    }
    Some((
        parts[3].to_string(),
        version,
        fragment,
        parts[6].to_string(),
        operation,
    ))
}

/// Shared fragment operation implementation used by HTTPS and QUIC.
///
/// Authorization happens before any filesystem or erasure-code operation, so adding a
/// faster transport cannot create a path around ML-DSA replay protection or the join key.
async fn dispatch_internal_fragment(
    st: &ClusterState,
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> InternalFragmentResult {
    if crate::pq::verify_request(headers, method, path, body, &st.pq_keys)
        .await
        .is_err()
    {
        return InternalFragmentResult::new(
            StatusCode::UNAUTHORIZED,
            b"invalid ML-DSA envelope".to_vec(),
        );
    }
    if !join_authorized(&st.cfg, headers) {
        return InternalFragmentResult::new(
            StatusCode::UNAUTHORIZED,
            b"invalid cluster join key".to_vec(),
        );
    }

    let Some((object, version, fragment, disk, operation)) = fragment_route(path) else {
        return InternalFragmentResult::new(
            StatusCode::NOT_FOUND,
            b"unknown fragment route".to_vec(),
        );
    };
    let fragment_file = fragment_path(&st.root, &disk, &object, version, fragment);

    match (method, operation.as_deref()) {
        ("PUT", None) => {
            if headers
                .get("x-kagi-cluster")
                .and_then(|value| value.to_str().ok())
                != Some(st.cfg.id.as_str())
            {
                return InternalFragmentResult::new(
                    StatusCode::FORBIDDEN,
                    b"cluster mismatch".to_vec(),
                );
            }
            let checksum = headers
                .get("x-kagi-checksum")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if blake3::hash(body).to_hex().to_string() != checksum {
                return InternalFragmentResult::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    b"checksum mismatch".to_vec(),
                );
            }
            match write_fragment_at_rest(
                &st.cfg,
                &fragment_file,
                &object,
                version,
                fragment,
                &disk,
                body,
            )
            .await
            {
                Ok(_) => InternalFragmentResult::empty(StatusCode::CREATED),
                Err(_) => InternalFragmentResult::empty(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        ("GET", None) => {
            match read_fragment_at_rest(&st.cfg, &fragment_file, &object, version, fragment, &disk)
                .await
            {
                Ok(bytes) => InternalFragmentResult::new(StatusCode::OK, bytes),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
                {
                    InternalFragmentResult::empty(StatusCode::NOT_FOUND)
                }
                Err(_) => InternalFragmentResult::empty(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        ("DELETE", None) => match tokio::fs::remove_file(fragment_file).await {
            Ok(_) => InternalFragmentResult::empty(StatusCode::NO_CONTENT),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                InternalFragmentResult::empty(StatusCode::NOT_FOUND)
            }
            Err(_) => InternalFragmentResult::empty(StatusCode::INTERNAL_SERVER_ERROR),
        },
        ("POST", Some("subchunks")) => {
            let request: SubchunkRequest = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(_) => {
                    return InternalFragmentResult::new(
                        StatusCode::BAD_REQUEST,
                        b"invalid subchunk request".to_vec(),
                    )
                }
            };
            match read_subchunks_at_rest(
                FragmentAtRestRef {
                    cfg: &st.cfg,
                    path: &fragment_file,
                    object: &object,
                    version,
                    fragment,
                    disk: &disk,
                },
                request.alpha,
                &request.indices,
            )
            .await
            {
                Ok(bytes) => InternalFragmentResult::new(StatusCode::OK, bytes),
                Err(error) => InternalFragmentResult::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    error.to_string().into_bytes(),
                ),
            }
        }
        ("POST", Some("project")) => {
            let request: ProjectionRequest = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(_) => {
                    return InternalFragmentResult::new(
                        StatusCode::BAD_REQUEST,
                        b"invalid projection request".to_vec(),
                    )
                }
            };
            let coefficient = match B64.decode(&request.coeff_b64) {
                Ok(value) => value,
                Err(_) => {
                    return InternalFragmentResult::new(
                        StatusCode::BAD_REQUEST,
                        b"invalid projection coefficients".to_vec(),
                    )
                }
            };
            if request.rows == 0
                || coefficient.is_empty()
                || !coefficient.len().is_multiple_of(request.rows)
            {
                return InternalFragmentResult::new(
                    StatusCode::BAD_REQUEST,
                    b"invalid projection matrix shape".to_vec(),
                );
            }
            let bytes = match read_fragment_at_rest(
                &st.cfg,
                &fragment_file,
                &object,
                version,
                fragment,
                &disk,
            )
            .await
            {
                Ok(value) => value,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
                {
                    return InternalFragmentResult::empty(StatusCode::NOT_FOUND)
                }
                Err(_) => return InternalFragmentResult::empty(StatusCode::INTERNAL_SERVER_ERROR),
            };
            if !bytes.len().is_multiple_of(request.rows) {
                return InternalFragmentResult::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    b"fragment/projection row mismatch".to_vec(),
                );
            }
            match st
                .erasure
                .linear_transform(
                    &bytes,
                    request.rows,
                    &coefficient,
                    coefficient.len() / request.rows,
                    bytes.len() / request.rows,
                )
                .await
            {
                Ok(output) => InternalFragmentResult::new(StatusCode::OK, output),
                Err(error) => InternalFragmentResult::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    error.to_string().into_bytes(),
                ),
            }
        }
        _ => InternalFragmentResult::new(
            StatusCode::METHOD_NOT_ALLOWED,
            b"method not allowed".to_vec(),
        ),
    }
}

async fn internal_put(
    State(st): State<ClusterState>,
    Path((object, version, fragment, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let path = format!("/internal/v1/fragment/{object}/{version}/{fragment}/{disk}");
    dispatch_internal_fragment(&st, "PUT", &path, &headers, &body)
        .await
        .into_response()
}

async fn internal_get(
    State(st): State<ClusterState>,
    Path((object, version, fragment, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let path = format!("/internal/v1/fragment/{object}/{version}/{fragment}/{disk}");
    dispatch_internal_fragment(&st, "GET", &path, &headers, &[])
        .await
        .into_response()
}

async fn internal_subchunks(
    State(st): State<ClusterState>,
    Path((object, version, fragment, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let path = format!("/internal/v1/fragment/{object}/{version}/{fragment}/{disk}/subchunks");
    dispatch_internal_fragment(&st, "POST", &path, &headers, &body)
        .await
        .into_response()
}

async fn internal_project(
    State(st): State<ClusterState>,
    Path((object, version, fragment, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let path = format!("/internal/v1/fragment/{object}/{version}/{fragment}/{disk}/project");
    dispatch_internal_fragment(&st, "POST", &path, &headers, &body)
        .await
        .into_response()
}

async fn internal_delete(
    State(st): State<ClusterState>,
    Path((object, version, fragment, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let path = format!("/internal/v1/fragment/{object}/{version}/{fragment}/{disk}");
    dispatch_internal_fragment(&st, "DELETE", &path, &headers, &[])
        .await
        .into_response()
}

#[cfg(feature = "quic")]
#[derive(Clone)]
struct QuicFragmentHandler {
    state: ClusterState,
}

#[cfg(feature = "quic")]
#[async_trait::async_trait]
impl crate::quic_transport::Handler for QuicFragmentHandler {
    async fn handle(
        &self,
        request: crate::quic_transport::Request,
    ) -> crate::quic_transport::Response {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in request.meta.headers {
            let Ok(name) = axum::http::HeaderName::from_bytes(name.as_bytes()) else {
                return crate::quic_transport::Response::error(400, "invalid header name");
            };
            let Ok(value) = axum::http::HeaderValue::from_str(&value) else {
                return crate::quic_transport::Response::error(400, "invalid header value");
            };
            headers.insert(name, value);
        }

        let result = dispatch_internal_fragment(
            &self.state,
            &request.meta.method,
            &request.meta.path,
            &headers,
            &request.body,
        )
        .await;
        crate::quic_transport::Response {
            status: result.status.as_u16(),
            message: result
                .status
                .canonical_reason()
                .unwrap_or("Kagi fragment response")
                .to_string(),
            body: result.body,
        }
    }
}

#[cfg(feature = "quic")]
pub async fn serve_quic(
    st: ClusterState,
    address: std::net::SocketAddr,
    tls: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let (endpoint, max_body_bytes) =
        crate::quic_transport::server_endpoint(address, tls, st.cfg.transport.max_frame_bytes)?;
    crate::quic_transport::serve(
        endpoint,
        max_body_bytes,
        Arc::new(QuicFragmentHandler { state: st }),
    )
    .await
}

/// Direct HTTP/HTTPS internal router. QUIC uses the same dispatcher above.
pub fn internal_router(st: ClusterState) -> Router {
    Router::new()
        .route(
            "/internal/v1/fragment/:obj/:ver/:frag/:disk",
            put(internal_put).get(internal_get).delete(internal_delete),
        )
        .route(
            "/internal/v1/fragment/:obj/:ver/:frag/:disk/subchunks",
            post(internal_subchunks),
        )
        .route(
            "/internal/v1/fragment/:obj/:ver/:frag/:disk/project",
            post(internal_project),
        )
        .with_state(st)
}

#[cfg(test)]
mod at_rest_encryption_tests {
    use super::*;

    fn encrypted_config() -> ClusterConfig {
        ClusterConfig {
            id: "test-cluster".into(),
            placement_salt: 1,
            hosts: Vec::new(),
            replication: 3,
            write_quorum: 2,
            chunk_replicas: 1,
            erasure: None,
            metadata_key_b64: Some(B64.encode([0x5au8; 32])),
            join_key_hash_hex: None,
            transport: DataTransportConfig::default(),
        }
    }

    #[test]
    fn chunked_fragment_envelope_round_trips_and_rejects_plaintext() {
        let cfg = encrypted_config();
        let mut plaintext = vec![0x41; FRAGMENT_AEAD_CHUNK_BYTES + 137];
        plaintext[FRAGMENT_AEAD_CHUNK_BYTES - 1] = 0x42;
        plaintext[FRAGMENT_AEAD_CHUNK_BYTES] = 0x43;
        let envelope =
            protect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-a", &plaintext).unwrap();

        assert!(envelope.starts_with(FRAGMENT_ENVELOPE_MAGIC));
        assert_ne!(envelope, plaintext);
        assert_eq!(
            unprotect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-a", &envelope).unwrap(),
            plaintext
        );
        assert!(
            unprotect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-a", &plaintext).is_err(),
            "plaintext must never silently bypass at-rest encryption"
        );
    }

    #[test]
    fn chunked_fragment_envelope_authenticates_header_ciphertext_and_identity() {
        let cfg = encrypted_config();
        let envelope =
            protect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-a", b"sensitive").unwrap();

        let mut tampered_header = envelope.clone();
        tampered_header[12] ^= 0x01;
        assert!(
            unprotect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-a", &tampered_header).is_err()
        );

        let mut tampered_ciphertext = envelope.clone();
        let last = tampered_ciphertext.len() - 1;
        tampered_ciphertext[last] ^= 0x80;
        assert!(
            unprotect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-a", &tampered_ciphertext)
                .is_err()
        );

        assert!(
            unprotect_fragment_at_rest(&cfg, "object-a", 7, 2, "disk-b", &envelope).is_err(),
            "ciphertext relocation to another disk identity must fail authentication"
        );
        assert!(
            unprotect_fragment_at_rest(&cfg, "object-a", 8, 2, "disk-a", &envelope).is_err(),
            "ciphertext relocation to another object version must fail authentication"
        );
    }

    #[tokio::test]
    async fn range_read_crosses_aead_chunk_boundary_without_full_fragment_read() {
        let cfg = encrypted_config();
        let mut plaintext = vec![0u8; FRAGMENT_AEAD_CHUNK_BYTES * 2 + 73];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let path =
            std::env::temp_dir().join(format!("kagi-fragment-aead-{}.frag", uuid::Uuid::new_v4()));
        write_fragment_at_rest(&cfg, &path, "object-a", 7, 2, "disk-a", &plaintext)
            .await
            .unwrap();

        let start = FRAGMENT_AEAD_CHUNK_BYTES - 31;
        let length = 127;
        let range = read_fragment_range_at_rest(
            FragmentAtRestRef {
                cfg: &cfg,
                path: &path,
                object: "object-a",
                version: 7,
                fragment: 2,
                disk: "disk-a",
            },
            start,
            length,
        )
        .await
        .unwrap();
        assert_eq!(range, plaintext[start..start + length]);

        let on_disk = tokio::fs::read(&path).await.unwrap();
        assert_ne!(on_disk, plaintext);
        assert!(on_disk.starts_with(FRAGMENT_ENVELOPE_MAGIC));
        tokio::fs::remove_file(path).await.unwrap();
    }
}
