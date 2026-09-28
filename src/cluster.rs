// Copyright (c) 2026 CK Cameron. All Rights Reserved. Proprietary and Confidential.
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
#[derive(Debug, Clone, Deserialize)]
// ---- Cluster topology and immutable object metadata ----------------------------
pub struct ClusterConfig {
    pub id: String,
    pub placement_salt: u64,
    pub hosts: Vec<PeerHost>,
    #[serde(default = "default_replication")]
    pub replication: usize,
    #[serde(default = "default_quorum")]
    pub write_quorum: usize,
    #[serde(default = "one_usize")]
    pub chunk_replicas: usize,
    #[serde(default)]
    pub erasure: Option<ErasureConfig>,
    #[serde(default)]
    pub metadata_key_b64: Option<String>,
    #[serde(default)]
    pub join_key_hash_hex: Option<String>,
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
pub struct PeerHost {
    pub id: String,
    pub endpoint: String,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub rack: Option<String>,
    pub disks: Vec<PeerDisk>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerDisk {
    pub id: String,
    pub capacity_bytes: u64,
    #[serde(default = "one")]
    pub weight: f64,
    #[serde(default)]
    pub device_path: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub wwn: Option<String>,
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
        .context("cluster.metadata_key_b64 is required for encrypted object metadata")?;
    let v = B64.decode(s).context("metadata_key_b64 must be base64")?;
    if v.len() != 32 {
        bail!("metadata_key_b64 must decode to exactly 32 bytes")
    }
    Ok(v.try_into().unwrap())
}
const PQ_METADATA_SUITE: &str = "XChaCha20-Poly1305-PQ128+BLAKE3-KDF+AAD+JSON+base64";
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
async fn rpc_store(
    st: &ClusterState,
    loc: &FragmentLocation,
    h: &FragmentHeader,
    data: &[u8],
) -> Result<()> {
    if loc.host == st.local_host {
        let p = fragment_path(&st.root, &loc.disk, &h.object_id, h.version, h.fragment);
        tokio::fs::create_dir_all(p.parent().unwrap()).await?;
        let tmp = p.with_extension("tmp");
        tokio::fs::write(&tmp, data).await?;
        let f = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
        f.sync_all().await?;
        tokio::fs::rename(tmp, p).await?;
        return Ok(());
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let url = format!(
        "{}/internal/v1/fragment/{}/{}/{}/{}",
        peer.endpoint.trim_end_matches('/'),
        h.object_id,
        h.version,
        h.fragment,
        loc.disk
    );
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}",
        h.object_id, h.version, h.fragment, loc.disk
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
        return Ok(tokio::fs::read(fragment_path(
            &st.root,
            &loc.disk,
            &m.object_id,
            m.version,
            loc.fragment,
        ))
        .await?);
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let url = format!(
        "{}/internal/v1/fragment/{}/{}/{}/{}",
        peer.endpoint.trim_end_matches('/'),
        m.object_id,
        m.version,
        loc.fragment,
        loc.disk
    );
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}",
        m.object_id, m.version, loc.fragment, loc.disk
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
async fn read_subchunks(path: PathBuf, alpha: usize, indices: &[usize]) -> Result<Vec<u8>> {
    if alpha == 0 || indices.is_empty() {
        bail!("subchunk request requires alpha>0 and at least one index")
    }
    let mut f = tokio::fs::File::open(path).await?;
    let len = f.metadata().await?.len() as usize;
    if len == 0 || !len.is_multiple_of(alpha) {
        bail!("fragment length {len} is not divisible by alpha={alpha}")
    }
    let row_len = len / alpha;
    let mut out = Vec::with_capacity(indices.len() * row_len);
    for &idx in indices {
        if idx >= alpha {
            bail!("subchunk index {idx} out of range for alpha={alpha}")
        }
        f.seek(std::io::SeekFrom::Start((idx * row_len) as u64))
            .await?;
        let start = out.len();
        out.resize(start + row_len, 0);
        f.read_exact(&mut out[start..]).await?;
    }
    Ok(out)
}
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
        return read_subchunks(
            fragment_path(&st.root, &loc.disk, &m.object_id, m.version, loc.fragment),
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
        let v = tokio::fs::read(fragment_path(
            &st.root,
            &loc.disk,
            &m.object_id,
            m.version,
            loc.fragment,
        ))
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
// ---- Internal fragment HTTP service and authorization --------------------------
fn join_authorized(cfg: &ClusterConfig, headers: &axum::http::HeaderMap) -> bool {
    let Some(want) = cfg.join_key_hash_hex.as_deref() else {
        return false;
    };
    let Some(raw) = headers.get("x-kagi-join-key").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(bytes) = B64.decode(raw) else {
        return false;
    };
    blake3::hash(&bytes).to_hex().to_string() == want
}
/// Implements the rpc delete replica step and keeps its validation and state transitions visible at the call site.
async fn rpc_delete_replica(
    st: &ClusterState,
    loc: &FragmentLocation,
    m: &ObjectManifest,
) -> Result<()> {
    if loc.host == st.local_host {
        let p = fragment_path(&st.root, &loc.disk, &m.object_id, m.version, loc.fragment);
        match tokio::fs::remove_file(p).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        return Ok(());
    }
    let peer = st
        .cfg
        .hosts
        .iter()
        .find(|x| x.id == loc.host)
        .context("peer missing")?;
    let url = format!(
        "{}/internal/v1/fragment/{}/{}/{}/{}",
        peer.endpoint.trim_end_matches('/'),
        m.object_id,
        m.version,
        loc.fragment,
        loc.disk
    );
    let path = format!(
        "/internal/v1/fragment/{}/{}/{}/{}",
        m.object_id, m.version, loc.fragment, loc.disk
    );
    let id = st.pq_identity.as_ref().context("PQ identity required")?;
    let auth = crate::pq::signed_headers(id, "DELETE", &path, &[])?;
    let r = crate::pq::apply_headers(st.client.delete(url), auth)
        .send()
        .await?;
    if !r.status().is_success() && r.status() != reqwest::StatusCode::NOT_FOUND {
        bail!("peer delete {}", r.status())
    }
    Ok(())
}
/// Implements the cleanup rebalanced replicas step and keeps its validation and state transitions visible at the call site.
pub async fn cleanup_rebalanced_replicas(
    st: &ClusterState,
    old: &ObjectManifest,
    new: &ObjectManifest,
) -> Result<()> {
    let keep: BTreeSet<_> = new
        .fragments
        .iter()
        .map(|x| (x.fragment, x.host.clone(), x.disk.clone()))
        .collect();
    for loc in &old.fragments {
        if !keep.contains(&(loc.fragment, loc.host.clone(), loc.disk.clone())) {
            rpc_delete_replica(st, loc, old).await?;
        }
    }
    Ok(())
}
/// Implements the internal put step and keeps its validation and state transitions visible at the call site.
async fn internal_put(
    State(st): State<ClusterState>,
    Path((obj, ver, frag, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path = format!("/internal/v1/fragment/{obj}/{ver}/{frag}/{disk}");
    if crate::pq::verify_request(&headers, "PUT", &path, &body, &st.pq_keys)
        .await
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "invalid ML-DSA envelope").into_response();
    }
    if !join_authorized(&st.cfg, &headers) {
        return (StatusCode::UNAUTHORIZED, "invalid cluster join key").into_response();
    }
    if headers.get("x-kagi-cluster").and_then(|x| x.to_str().ok()) != Some(st.cfg.id.as_str()) {
        return (StatusCode::FORBIDDEN, "cluster mismatch").into_response();
    }
    let want = headers
        .get("x-kagi-checksum")
        .and_then(|x| x.to_str().ok())
        .unwrap_or("");
    if blake3::hash(&body).to_hex().to_string() != want {
        return (StatusCode::UNPROCESSABLE_ENTITY, "checksum mismatch").into_response();
    }
    let p = fragment_path(&st.root, &disk, &obj, ver, frag);
    if let Some(parent) = p.parent() {
        if tokio::fs::create_dir_all(parent).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    let tmp = p.with_extension("tmp");
    if tokio::fs::write(&tmp, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match tokio::fs::rename(tmp, p).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
/// Implements the internal get step and keeps its validation and state transitions visible at the call site.
async fn internal_get(
    State(st): State<ClusterState>,
    Path((obj, ver, frag, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let path = format!("/internal/v1/fragment/{obj}/{ver}/{frag}/{disk}");
    if crate::pq::verify_request(&headers, "GET", &path, &[], &st.pq_keys)
        .await
        .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !join_authorized(&st.cfg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match tokio::fs::read(fragment_path(&st.root, &disk, &obj, ver, frag)).await {
        Ok(v) => (StatusCode::OK, v).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
/// Implements the internal subchunks step and keeps its validation and state transitions visible at the call site.
async fn internal_subchunks(
    State(st): State<ClusterState>,
    Path((obj, ver, frag, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path = format!("/internal/v1/fragment/{obj}/{ver}/{frag}/{disk}/subchunks");
    if crate::pq::verify_request(&headers, "POST", &path, &body, &st.pq_keys)
        .await
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "invalid ML-DSA envelope").into_response();
    }
    if !join_authorized(&st.cfg, &headers) {
        return (StatusCode::UNAUTHORIZED, "invalid cluster join key").into_response();
    }
    let req: SubchunkRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid subchunk request").into_response(),
    };
    match read_subchunks(
        fragment_path(&st.root, &disk, &obj, ver, frag),
        req.alpha,
        &req.indices,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, v).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response(),
    }
}
/// Implements the internal project step and keeps its validation and state transitions visible at the call site.
async fn internal_project(
    State(st): State<ClusterState>,
    Path((obj, ver, frag, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path = format!("/internal/v1/fragment/{obj}/{ver}/{frag}/{disk}/project");
    if crate::pq::verify_request(&headers, "POST", &path, &body, &st.pq_keys)
        .await
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "invalid ML-DSA envelope").into_response();
    }
    if !join_authorized(&st.cfg, &headers) {
        return (StatusCode::UNAUTHORIZED, "invalid cluster join key").into_response();
    }
    let req: ProjectionRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid projection request").into_response(),
    };
    let coeff = match B64.decode(&req.coeff_b64) {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid projection coefficients").into_response()
        }
    };
    if req.rows == 0 || coeff.is_empty() || !coeff.len().is_multiple_of(req.rows) {
        return (StatusCode::BAD_REQUEST, "invalid projection matrix shape").into_response();
    }
    let v = match tokio::fs::read(fragment_path(&st.root, &disk, &obj, ver, frag)).await {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    if !v.len().is_multiple_of(req.rows) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fragment/projection row mismatch",
        )
            .into_response();
    }
    match st
        .erasure
        .linear_transform(
            &v,
            req.rows,
            &coeff,
            coeff.len() / req.rows,
            v.len() / req.rows,
        )
        .await
    {
        Ok(out) => (StatusCode::OK, out).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response(),
    }
}
/// Implements the internal delete step and keeps its validation and state transitions visible at the call site.
async fn internal_delete(
    State(st): State<ClusterState>,
    Path((obj, ver, frag, disk)): Path<(String, u64, u32, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let path = format!("/internal/v1/fragment/{obj}/{ver}/{frag}/{disk}");
    if crate::pq::verify_request(&headers, "DELETE", &path, &[], &st.pq_keys)
        .await
        .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !join_authorized(&st.cfg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let p = fragment_path(&st.root, &disk, &obj, ver, frag);
    match tokio::fs::remove_file(p).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
/// Implements the internal router step and keeps its validation and state transitions visible at the call site.
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
