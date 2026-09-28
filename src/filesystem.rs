// Copyright (c) 2026 CK Cameron. All Rights Reserved. Proprietary and Confidential.
//! Kagi filesystem namespace overlay and ACL model.
//!
//! Directory metadata is stored with the same protected object substrate as ordinary data.
//! Parent/child links and index snapshots are intentionally reconstructable from object
//! metadata. ACL evaluation follows the NFSv4-inspired allow/deny model and supports Unix
//! and Active Directory style principals without making either identity source mandatory.

// Filesystem namespace overlay, ACL evaluation, decentralized index, and bottom-up reconstruction.
//! Filesystem namespace overlay and NFSv4-style ACL model.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
/// Supported FsObjectType states or operations.
pub enum FsObjectType {
    #[default]
    File,
    Directory,
}
/// NFSv4-inspired ACE. `who` accepts OWNER@, GROUP@, EVERYONE@, unix:<uid>, unix-group:<gid>, ad:<sid>, ad-group:<sid>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ace {
    pub ace_type: String,
    pub who: String,
    pub permissions: BTreeSet<String>,
    #[serde(default)]
    pub flags: BTreeSet<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Kagi state or configuration used by the ObjectAcl path.
pub struct ObjectAcl {
    pub owner: String,
    pub group: String,
    #[serde(default)]
    pub entries: Vec<Ace>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the ChildRef path.
pub struct ChildRef {
    pub name: String,
    pub object_id: String,
    pub key: String,
    pub object_type: FsObjectType,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the FsMetadata path.
pub struct FsMetadata {
    /// Security classification preserved with immutable versions; only an admin may change it.
    #[serde(default)]
    pub privileged: bool,
    pub object_type: FsObjectType,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub parent_object_id: Option<String>,
    #[serde(default)]
    pub parent_key: Option<String>,
    /// Authoritative child links for directory objects. These links plus every child's parent link make the tree self-describing.
    #[serde(default)]
    pub children: Vec<ChildRef>,
    /// For directories, the logical contents are the child object references. Files carry no namespace contents here.
    #[serde(default)]
    pub contents: Vec<String>,
    #[serde(default)]
    pub acl: ObjectAcl,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the IndexEntry path.
pub struct IndexEntry {
    pub path: String,
    pub key: String,
    pub object_id: String,
    pub version: u64,
    pub object_type: FsObjectType,
    pub parent_key: Option<String>,
    pub acl: ObjectAcl,
    pub updated_ms: u128,
    pub origin: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexSnapshot {
    pub entries: BTreeMap<String, IndexEntry>,
}
/// Per-host LWW overlay index. It is deliberately non-authoritative: object metadata can rebuild it bottom-up.
#[derive(Clone)]
pub struct FsIndex {
    root: PathBuf,
    host: String,
    inner: Arc<RwLock<IndexSnapshot>>,
}
impl FsIndex {
    pub async fn open(root: PathBuf, host: String) -> Result<Self> {
        tokio::fs::create_dir_all(&root).await?;
        let p = root.join("fs-index.json");
        let snap = match tokio::fs::read(&p).await {
            Ok(v) => serde_json::from_slice(&v)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IndexSnapshot::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            root,
            host,
            inner: Arc::new(RwLock::new(snap)),
        })
    }
    async fn persist(&self) -> Result<()> {
        let v = serde_json::to_vec(&*self.inner.read().await)?;
        let t = self.root.join("fs-index.tmp");
        tokio::fs::write(&t, v).await?;
        tokio::fs::rename(t, self.root.join("fs-index.json")).await?;
        Ok(())
    }
    pub async fn upsert(&self, mut e: IndexEntry) -> Result<()> {
        e.origin = self.host.clone();
        let mut s = self.inner.write().await;
        let replace = s
            .entries
            .get(&e.path)
            .map(|x| (e.updated_ms, &e.origin) > (x.updated_ms, &x.origin))
            .unwrap_or(true);
        if replace {
            s.entries.insert(e.path.clone(), e);
        }
        drop(s);
        self.persist().await
    }
    pub async fn merge(&self, other: IndexSnapshot) -> Result<usize> {
        let mut n = 0;
        let mut s = self.inner.write().await;
        for (p, e) in other.entries {
            let replace = s
                .entries
                .get(&p)
                .map(|x| (e.updated_ms, &e.origin) > (x.updated_ms, &x.origin))
                .unwrap_or(true);
            if replace {
                s.entries.insert(p, e);
                n += 1
            }
        }
        drop(s);
        if n > 0 {
            self.persist().await?
        }
        Ok(n)
    }
    pub async fn snapshot(&self) -> IndexSnapshot {
        self.inner.read().await.clone()
    }
}
/// Implements the now ms step and keeps its validation and state transitions visible at the call site.
pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthIdentity {
    pub principals: BTreeSet<String>,
}
impl AuthIdentity {
    pub fn from_headers(h: &axum::http::HeaderMap) -> Self {
        let mut p = BTreeSet::new();
        if let Some(v) = h.get("x-kagi-unix-uid").and_then(|x| x.to_str().ok()) {
            p.insert(format!("unix:{v}"));
        }
        if let Some(v) = h.get("x-kagi-unix-gids").and_then(|x| x.to_str().ok()) {
            for g in v.split(',') {
                p.insert(format!("unix-group:{}", g.trim()));
            }
        }
        if let Some(v) = h.get("x-kagi-ad-sid").and_then(|x| x.to_str().ok()) {
            p.insert(format!("ad:{v}"));
        }
        if let Some(v) = h.get("x-kagi-ad-group-sids").and_then(|x| x.to_str().ok()) {
            for g in v.split(',') {
                p.insert(format!("ad-group:{}", g.trim()));
            }
        }
        p.insert("EVERYONE@".into());
        Self { principals: p }
    }
    pub fn allows(&self, acl: &ObjectAcl, permission: &str) -> bool {
        let mut allowed = false;
        for ace in &acl.entries {
            let applies = ace.who == "EVERYONE@"
                || ace.who == "OWNER@" && self.principals.contains(&acl.owner)
                || ace.who == "GROUP@" && self.principals.contains(&acl.group)
                || self.principals.contains(&ace.who);
            if applies && ace.permissions.contains(permission) {
                if ace.ace_type.eq_ignore_ascii_case("deny") {
                    return false;
                }
                if ace.ace_type.eq_ignore_ascii_case("allow") {
                    allowed = true
                }
            }
        }
        allowed
    }
}
/// Reconstruct a path from any leaf by following parent_key links. This is intentionally independent of the overlay index.
pub fn reconstruct_bottom_up<'a>(
    leaf: &'a crate::cluster::ObjectManifest,
    all: &'a BTreeMap<String, crate::cluster::ObjectManifest>,
) -> Result<Vec<String>> {
    let mut out = vec![leaf.key.clone()];
    let mut cur = leaf;
    let mut seen = BTreeSet::new();
    seen.insert(cur.object_id.clone());
    while let Some(fs) = &cur.fs {
        let Some(pk) = &fs.parent_key else { break };
        let p = all
            .get(pk)
            .with_context(|| format!("missing parent object {pk}"))?;
        if !seen.insert(p.object_id.clone()) {
            anyhow::bail!("filesystem parent cycle detected")
        };
        out.push(p.key.clone());
        cur = p;
    }
    out.reverse();
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn acl() -> ObjectAcl {
        ObjectAcl {
            owner: "unix:1000".into(),
            group: "unix-group:100".into(),
            entries: vec![
                Ace {
                    ace_type: "allow".into(),
                    who: "EVERYONE@".into(),
                    permissions: BTreeSet::from(["read_data".into()]),
                    flags: BTreeSet::new(),
                },
                Ace {
                    ace_type: "deny".into(),
                    who: "unix:2000".into(),
                    permissions: BTreeSet::from(["read_data".into()]),
                    flags: BTreeSet::new(),
                },
                Ace {
                    ace_type: "allow".into(),
                    who: "OWNER@".into(),
                    permissions: BTreeSet::from(["write_data".into()]),
                    flags: BTreeSet::new(),
                },
            ],
        }
    }
    #[test]
    fn explicit_deny_overrides_allow() {
        let id = AuthIdentity {
            principals: BTreeSet::from(["EVERYONE@".into(), "unix:2000".into()]),
        };
        assert!(!id.allows(&acl(), "read_data"));
    }
    #[test]
    fn owner_permission_matches_owner_principal() {
        let id = AuthIdentity {
            principals: BTreeSet::from(["EVERYONE@".into(), "unix:1000".into()]),
        };
        assert!(id.allows(&acl(), "write_data"));
    }
}
