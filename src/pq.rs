// Copyright (c) 2026 CK Cameron. All Rights Reserved. Proprietary and Confidential.
//! Kagi post-quantum signing, peer trust, and replay protection.
//!
//! Internal control traffic is authenticated with ML-DSA identities and bounded replay
//! state. Key identifiers, validity windows, revocation state, per-peer session epochs, and
//! monotonic sequence tracking are kept explicit so key rotation does not weaken admission
//! or restart-time replay guarantees.

// Post-quantum internal-request authentication, replay protection, session epochs, and ML-DSA key handling.
//! Mandatory ML-DSA-87 authentication for all internal cluster protocols.
//! Keys are identified by a BLAKE3 key id and can overlap during Raft-managed rotation.
use anyhow::{bail, Context, Result};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::{Mutex, RwLock};
pub const PQ_CONTEXT: &[u8] = b"Kagi distributed storage-v19-internal-auth";
pub const MAX_SKEW_MS: u128 = 30_000;
pub const MAX_NONCES_PER_PEER: usize = 4096;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPqKey {
    pub node_id: String,
    pub key_id: String,
    pub public_key_b64: String,
    pub not_before_ms: u128,
    pub not_after_ms: Option<u128>,
    #[serde(default)]
    pub revoked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SenderSessionDisk {
    epoch: u64,
    sequence: u64,
}
#[derive(Debug, Clone)] // ---- ML-DSA identities and replicated trust keys -------------------------------
/// Kagi state or configuration used by the LocalPqIdentity path.
pub struct LocalPqIdentity {
    pub node_id: String,
    pub key_id: String,
    pub secret: PathBuf,
    session: Arc<StdMutex<SenderSession>>,
}
#[derive(Debug)]
struct SenderSession {
    epoch: u64,
    sequence: u64,
    path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PeerSessionDisk {
    epoch: u64,
    #[serde(default)]
    highest_sequence: u64,
    #[serde(default)]
    seen: Vec<u64>,
}
const SESSION_REORDER_WINDOW: u64 = 4096;
#[derive(Debug, Default)]
struct PeerSessionStore {
    path: Option<PathBuf>,
    peers: BTreeMap<String, PeerSessionDisk>,
}
#[derive(Debug, Clone, Default)]
/// Kagi state or configuration used by the RuntimeKeyring path.
pub struct RuntimeKeyring {
    /// Trusted ML-DSA verification keys, indexed by key id.
    pub keys: Arc<RwLock<BTreeMap<String, TrustedPqKey>>>,
    /// Replay cache is indexed by authenticated node id, not key id, so key
    /// rotation cannot create a fresh replay namespace for the same peer.
    nonces: Arc<Mutex<BTreeMap<String, BTreeMap<String, u128>>>>,
    /// Persisted highest authenticated (session epoch, sequence) for each peer.
    /// This closes the restart replay window left by the in-memory nonce cache.
    sessions: Arc<Mutex<PeerSessionStore>>,
}
impl RuntimeKeyring {
    pub async fn configure_peer_sessions(&self, path: PathBuf) -> Result<()> {
        let peers = match fs::read(&path) {
            Ok(v) => serde_json::from_slice(&v)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut s = self.sessions.lock().await;
        s.path = Some(path);
        s.peers = peers;
        Ok(())
    }
    async fn check_and_record_session(&self, node: &str, epoch: u64, sequence: u64) -> Result<()> {
        if epoch == 0 || sequence == 0 {
            bail!("invalid PQ session epoch/sequence");
        }
        let mut s = self.sessions.lock().await;
        let mut peer = s.peers.get(node).cloned().unwrap_or_default();
        if epoch < peer.epoch {
            bail!("stale PQ session epoch");
        }
        if epoch > peer.epoch {
            // A newer epoch is accepted only because it is inside the verified
            // ML-DSA envelope. Reset the sequence replay window for the new session.
            peer = PeerSessionDisk {
                epoch,
                highest_sequence: 0,
                seen: Vec::new(),
            };
        }
        let floor = peer.highest_sequence.saturating_sub(SESSION_REORDER_WINDOW);
        if sequence <= floor || peer.seen.contains(&sequence) {
            bail!("replayed or stale PQ session sequence");
        }
        peer.highest_sequence = peer.highest_sequence.max(sequence);
        let new_floor = peer.highest_sequence.saturating_sub(SESSION_REORDER_WINDOW);
        peer.seen.retain(|x| *x > new_floor);
        peer.seen.push(sequence);
        s.peers.insert(node.to_string(), peer);
        if let Some(path) = s.path.clone() {
            let tmp = path.with_extension("tmp");
            fs::write(&tmp, serde_json::to_vec(&s.peers)?)?;
            fs::rename(tmp, path)?;
        }
        Ok(())
    }
    /// Atomically reject an already-seen nonce and record a new one.  Entries
    /// expire at the end of the signed request's acceptance window.  The cache
    /// is deliberately bounded per peer to prevent a valid but faulty peer from
    /// consuming unbounded memory.
    async fn check_and_record_nonce(
        &self,
        node: &str,
        nonce: &str,
        ts: u128,
        now: u128,
    ) -> Result<()> {
        if nonce.len() < 16 || nonce.len() > 128 {
            bail!("invalid ML-DSA nonce length");
        }
        let expiry = ts.saturating_add(MAX_SKEW_MS);
        let mut all = self.nonces.lock().await;
        let peer = all.entry(node.to_string()).or_default();
        peer.retain(|_, e| *e >= now);
        if peer.contains_key(nonce) {
            bail!("replayed ML-DSA request nonce");
        }
        if peer.len() >= MAX_NONCES_PER_PEER {
            if let Some(oldest) = peer.iter().min_by_key(|(_, e)| **e).map(|(n, _)| n.clone()) {
                peer.remove(&oldest);
            }
        }
        peer.insert(nonce.to_string(), expiry);
        Ok(())
    }
}
/// Implements the generate identity step and keeps its validation and state transitions visible at the call site.
pub fn generate_identity(public: &Path, secret: &Path) -> Result<()> {
    let (pk, sk) = ml_dsa_87::try_keygen().map_err(|e| anyhow::anyhow!(e))?;
    fs::write(public, B64.encode(pk.into_bytes()))?;
    fs::write(secret, B64.encode(sk.into_bytes()))?;
    Ok(())
}
/// Implements the public key b64 step and keeps its validation and state transitions visible at the call site.
pub fn public_key_b64(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}
/// Implements the key id from public b64 step and keeps its validation and state transitions visible at the call site.
pub fn key_id_from_public_b64(s: &str) -> Result<String> {
    let raw = B64.decode(s.trim())?;
    Ok(blake3::hash(&raw).to_hex().to_string())
}
/// Implements the local identity step and keeps its validation and state transitions visible at the call site.
pub fn local_identity(
    node_id: String,
    public: &Path,
    secret: PathBuf,
    session_path: PathBuf,
) -> Result<LocalPqIdentity> {
    let p = public_key_b64(public)?;
    if let Some(parent) = session_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let old = match fs::read(&session_path) {
        Ok(v) => serde_json::from_slice::<SenderSessionDisk>(&v)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SenderSessionDisk {
            epoch: 0,
            sequence: 0,
        },
        Err(e) => return Err(e.into()),
    };
    let epoch = old
        .epoch
        .checked_add(1)
        .context("PQ session epoch exhausted")?;
    let d = SenderSessionDisk { epoch, sequence: 0 };
    let tmp = session_path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec(&d)?)?;
    fs::rename(tmp, &session_path)?;
    Ok(LocalPqIdentity {
        node_id,
        key_id: key_id_from_public_b64(&p)?,
        secret,
        session: Arc::new(StdMutex::new(SenderSession {
            epoch,
            sequence: 0,
            path: session_path,
        })),
    })
}
/// Implements the now ms step and keeps its validation and state transitions visible at the call site.
fn now_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}
/// Kagi state or configuration used by the CanonicalRequest path.
struct CanonicalRequest<'a> {
    node: &'a str,
    key_id: &'a str,
    epoch: u64,
    sequence: u64,
    ts: u128,
    nonce: &'a str,
    method: &'a str,
    path: &'a str,
    body_hash: &'a str,
}
/// Implements the canonical step and keeps its validation and state transitions visible at the call site.
fn canonical(r: &CanonicalRequest<'_>) -> Vec<u8> {
    format!(
        "KAGI-MLDSA-HTTP-V3\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        r.node,
        r.key_id,
        r.epoch,
        r.sequence,
        r.ts,
        r.nonce,
        r.method.to_ascii_uppercase(),
        r.path,
        r.body_hash
    )
    .into_bytes()
}
/// Implements the sign bytes step and keeps its validation and state transitions visible at the call site.
fn sign_bytes(secret: &Path, msg: &[u8]) -> Result<String> {
    let raw = B64.decode(fs::read_to_string(secret)?.trim())?;
    let arr: [u8; ml_dsa_87::SK_LEN] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-87 secret key length"))?;
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(arr).map_err(|e| anyhow::anyhow!(e))?;
    let sig = sk
        .try_sign(msg, PQ_CONTEXT)
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(B64.encode(sig))
}
// ---- Detached request envelope construction ------------------------------------
pub fn signed_headers(
    id: &LocalPqIdentity,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<(&'static str, String)>> {
    let (epoch, sequence) = {
        let mut s = id
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("PQ session lock poisoned"))?;
        s.sequence = s
            .sequence
            .checked_add(1)
            .context("PQ session sequence exhausted")?;
        let d = SenderSessionDisk {
            epoch: s.epoch,
            sequence: s.sequence,
        };
        let tmp = s.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(&d)?)?;
        fs::rename(tmp, &s.path)?;
        (s.epoch, s.sequence)
    };
    let ts = now_ms()?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let bh = blake3::hash(body).to_hex().to_string();
    let sig = sign_bytes(
        &id.secret,
        &canonical(&CanonicalRequest {
            node: &id.node_id,
            key_id: &id.key_id,
            epoch,
            sequence,
            ts,
            nonce: &nonce,
            method,
            path,
            body_hash: &bh,
        }),
    )?;
    Ok(vec![
        ("x-kagi-pq-node", id.node_id.clone()),
        ("x-kagi-pq-key-id", id.key_id.clone()),
        ("x-kagi-pq-session-epoch", epoch.to_string()),
        ("x-kagi-pq-sequence", sequence.to_string()),
        ("x-kagi-pq-time", ts.to_string()),
        ("x-kagi-pq-nonce", nonce),
        ("x-kagi-pq-body", bh),
        ("x-kagi-pq-signature", sig),
    ])
}
// ---- Verification, replay cache, durable peer epoch/sequence enforcement -------
pub async fn verify_request(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    keys: &RuntimeKeyring,
) -> Result<String> {
    let get = |n: &str| -> Result<String> {
        Ok(headers
            .get(n)
            .context(format!("missing {n}"))?
            .to_str()?
            .to_string())
    };
    let node = get("x-kagi-pq-node")?;
    let kid = get("x-kagi-pq-key-id")?;
    let epoch: u64 = get("x-kagi-pq-session-epoch")?.parse()?;
    let sequence: u64 = get("x-kagi-pq-sequence")?.parse()?;
    let ts: u128 = get("x-kagi-pq-time")?.parse()?;
    let nonce = get("x-kagi-pq-nonce")?;
    let claimed = get("x-kagi-pq-body")?;
    let sigraw = B64.decode(get("x-kagi-pq-signature")?)?;
    let now = now_ms()?;
    if now.abs_diff(ts) > MAX_SKEW_MS {
        bail!("stale ML-DSA request")
    };
    let actual = blake3::hash(body).to_hex().to_string();
    if actual != claimed {
        bail!("signed body hash mismatch")
    };
    let k = keys
        .keys
        .read()
        .await
        .get(&kid)
        .cloned()
        .context("untrusted ML-DSA key id")?;
    if k.node_id != node
        || k.revoked
        || ts < k.not_before_ms
        || k.not_after_ms.map(|x| ts > x).unwrap_or(false)
    {
        bail!("ML-DSA key not valid for node/time")
    };
    let raw = B64.decode(&k.public_key_b64)?;
    let arr: [u8; ml_dsa_87::PK_LEN] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA public key"))?;
    let pk = ml_dsa_87::PublicKey::try_from_bytes(arr).map_err(|e| anyhow::anyhow!(e))?;
    let sig: [u8; ml_dsa_87::SIG_LEN] = sigraw
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA signature"))?;
    if !pk.verify(
        &canonical(&CanonicalRequest {
            node: &node,
            key_id: &kid,
            epoch,
            sequence,
            ts,
            nonce: &nonce,
            method,
            path,
            body_hash: &actual,
        }),
        &sig,
        PQ_CONTEXT,
    ) {
        bail!("ML-DSA authentication failed")
    };
    // Signature first: unauthenticated traffic cannot advance durable replay state.
    keys.check_and_record_session(&node, epoch, sequence)
        .await?;
    keys.check_and_record_nonce(&node, &nonce, ts, now).await?;
    Ok(node)
}
/// Implements the apply headers step and keeps its validation and state transitions visible at the call site.
pub fn apply_headers(
    mut b: reqwest::RequestBuilder,
    headers: Vec<(&'static str, String)>,
) -> reqwest::RequestBuilder {
    for (k, v) in headers {
        b = b.header(k, v)
    }
    b
}
