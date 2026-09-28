// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi sparse virtual block-volume layer.
//!
//! Virtual volumes map logical block ranges onto immutable Kagi objects while Raft metadata
//! tracks the active extent map. This module also models stable SCSI identity and SCSI-3
//! persistent reservations so the same protected storage can be presented safely to VM and
//! clustered-host consumers.

// Sparse zvol-like block-volume layer, SCSI identity, thin extents, and persistent reservations.
//! Sparse virtual block volumes built from immutable Kagi objects.
//! The block map is Raft metadata; data extents are ordinary protected objects.
use crate::cluster::{get_object_version, put_object, ClusterState, ObjectManifest};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const DEFAULT_EXTENT_BYTES: u64 = 4 * 1024 * 1024;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Supported PrType states or operations.
pub enum PrType {
    WriteExclusive,
    ExclusiveAccess,
    WriteExclusiveRegistrantsOnly,
    ExclusiveAccessRegistrantsOnly,
    WriteExclusiveAllRegistrants,
    ExclusiveAccessAllRegistrants,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Kagi state or configuration used by the PrRegistration path.
pub struct PrRegistration {
    pub key: u64,
    pub aptpl: bool,
    pub registered_at_unix_ms: u128,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the PrReservation path.
pub struct PrReservation {
    pub holder: String,
    pub key: u64,
    pub reservation_type: PrType,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Kagi state or configuration used by the PersistentReservation path.
pub struct PersistentReservation {
    pub generation: u64,
    pub registrations: BTreeMap<String, PrRegistration>,
    pub reservation: Option<PrReservation>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
/// Supported PrOut states or operations.
pub enum PrOut {
    Register {
        initiator: String,
        current_key: u64,
        new_key: u64,
        #[serde(default)]
        aptpl: bool,
        #[serde(default)]
        ignore_existing: bool,
    },
    Reserve {
        initiator: String,
        key: u64,
        reservation_type: PrType,
    },
    Release {
        initiator: String,
        key: u64,
        reservation_type: PrType,
    },
    Clear {
        initiator: String,
        key: u64,
    },
    Preempt {
        initiator: String,
        key: u64,
        service_action_key: u64,
        reservation_type: PrType,
        #[serde(default)]
        abort: bool,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the PrIn path.
pub struct PrIn {
    pub generation: u64,
    pub registrations: BTreeMap<String, PrRegistration>,
    pub reservation: Option<PrReservation>,
}
/// Implements the is reg step and keeps its validation and state transitions visible at the call site.
fn is_reg(pr: &PersistentReservation, i: &str) -> bool {
    pr.registrations.contains_key(i)
}
/// Implements the pr allows read step and keeps its validation and state transitions visible at the call site.
pub fn pr_allows_read(pr: &PersistentReservation, initiator: Option<&str>) -> bool {
    let Some(r) = &pr.reservation else {
        return true;
    };
    let Some(i) = initiator else { return false };
    match r.reservation_type {
        PrType::ExclusiveAccess
        | PrType::ExclusiveAccessRegistrantsOnly
        | PrType::ExclusiveAccessAllRegistrants => match r.reservation_type {
            PrType::ExclusiveAccess => i == r.holder,
            _ => is_reg(pr, i),
        },
        _ => true,
    }
}
/// Implements the pr allows write step and keeps its validation and state transitions visible at the call site.
pub fn pr_allows_write(pr: &PersistentReservation, initiator: Option<&str>) -> bool {
    let Some(r) = &pr.reservation else {
        return true;
    };
    let Some(i) = initiator else { return false };
    match r.reservation_type {
        PrType::WriteExclusive | PrType::ExclusiveAccess => i == r.holder,
        PrType::WriteExclusiveRegistrantsOnly
        | PrType::ExclusiveAccessRegistrantsOnly
        | PrType::WriteExclusiveAllRegistrants
        | PrType::ExclusiveAccessAllRegistrants => is_reg(pr, i),
    }
}
/// Implements the apply pr out step and keeps its validation and state transitions visible at the call site.
pub fn apply_pr_out(pr: &mut PersistentReservation, op: &PrOut) -> Result<()> {
    match op {
        PrOut::Register {
            initiator,
            current_key,
            new_key,
            aptpl,
            ignore_existing,
        } => {
            let old = pr.registrations.get(initiator).map(|x| x.key).unwrap_or(0);
            if !*ignore_existing && old != *current_key {
                bail!("reservation conflict: registration key mismatch")
            }
            if *new_key == 0 {
                pr.registrations.remove(initiator);
                if pr.reservation.as_ref().map(|r| r.holder.as_str()) == Some(initiator.as_str()) {
                    pr.reservation = None;
                }
            } else {
                pr.registrations.insert(
                    initiator.clone(),
                    PrRegistration {
                        key: *new_key,
                        aptpl: *aptpl,
                        registered_at_unix_ms: crate::filesystem::now_ms(),
                    },
                );
            }
        }
        PrOut::Reserve {
            initiator,
            key,
            reservation_type,
        } => {
            let reg = pr
                .registrations
                .get(initiator)
                .ok_or_else(|| anyhow::anyhow!("reservation conflict: initiator not registered"))?;
            if reg.key != *key {
                bail!("reservation conflict: key mismatch")
            }
            if let Some(r) = &pr.reservation {
                if r.holder != *initiator || r.key != *key {
                    bail!("reservation conflict: reservation already held")
                }
            }
            pr.reservation = Some(PrReservation {
                holder: initiator.clone(),
                key: *key,
                reservation_type: *reservation_type,
            });
        }
        PrOut::Release {
            initiator,
            key,
            reservation_type,
        } => {
            let Some(r) = &pr.reservation else {
                return Ok(());
            };
            if r.holder != *initiator || r.key != *key || r.reservation_type != *reservation_type {
                bail!("reservation conflict: release does not match reservation")
            }
            pr.reservation = None;
        }
        PrOut::Clear { initiator, key } => {
            let reg = pr
                .registrations
                .get(initiator)
                .ok_or_else(|| anyhow::anyhow!("reservation conflict: initiator not registered"))?;
            if reg.key != *key {
                bail!("reservation conflict: key mismatch")
            }
            pr.registrations.clear();
            pr.reservation = None;
        }
        PrOut::Preempt {
            initiator,
            key,
            service_action_key,
            reservation_type,
            abort: _,
        } => {
            let reg = pr
                .registrations
                .get(initiator)
                .ok_or_else(|| anyhow::anyhow!("reservation conflict: initiator not registered"))?;
            if reg.key != *key {
                bail!("reservation conflict: key mismatch")
            }
            let victims: Vec<String> = pr
                .registrations
                .iter()
                .filter(|(i, r)| i.as_str() != initiator && r.key == *service_action_key)
                .map(|(i, _)| i.clone())
                .collect();
            if victims.is_empty()
                && pr.reservation.as_ref().map(|r| r.key) != Some(*service_action_key)
            {
                bail!("reservation conflict: service action key not present")
            }
            for v in victims {
                pr.registrations.remove(&v);
            }
            if pr.reservation.as_ref().map(|r| r.key) == Some(*service_action_key) {
                pr.reservation = Some(PrReservation {
                    holder: initiator.clone(),
                    key: *key,
                    reservation_type: *reservation_type,
                });
            }
        }
    }
    pr.generation = pr.generation.saturating_add(1);
    Ok(())
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Supported VolumePresentation states or operations.
pub enum VolumePresentation {
    Raw,
    Nbd,
    Iscsi,
    VirtioScsi,
    VirtualSas,
    VmwarePvscsi,
    HypervScsi,
    Qcow2,
    Vmdk,
    Vhdx,
    Kubernetes,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the VolumeExtent path.
pub struct VolumeExtent {
    pub extent: u64,
    pub manifest: ObjectManifest,
    pub generation: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the VolumeRecord path.
pub struct VolumeRecord {
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    pub logical_block_bytes: u32,
    pub extent_bytes: u64,
    pub generation: u64,
    pub created_at_unix_ms: u128,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default = "thin_default")]
    pub thin_provisioned: bool,
    #[serde(default)]
    pub scsi: ScsiIdentity,
    #[serde(default)]
    pub presentations: Vec<VolumePresentation>,
    #[serde(default)]
    pub extents: BTreeMap<u64, VolumeExtent>,
    #[serde(default)]
    pub persistent_reservation: PersistentReservation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Kagi state or configuration used by the ScsiIdentity path.
pub struct ScsiIdentity {
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub serial: String,
    pub naa: String,
}
impl Default for ScsiIdentity {
    fn default() -> Self {
        Self {
            vendor: "KAGI".into(),
            product: "KAGI ZVOL".into(),
            revision: "0026".into(),
            serial: String::new(),
            naa: String::new(),
        }
    }
}
/// Implements the thin default step and keeps its validation and state transitions visible at the call site.
fn thin_default() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeCreate {
    pub id: Option<String>,
    pub name: String,
    pub size_bytes: u64,
    #[serde(default = "lbs")]
    pub logical_block_bytes: u32,
    #[serde(default = "extent")]
    pub extent_bytes: u64,
    #[serde(default = "thin_default")]
    pub thin_provisioned: bool,
    #[serde(default)]
    pub presentations: Vec<VolumePresentation>,
}
/// Implements the lbs step and keeps its validation and state transitions visible at the call site.
fn lbs() -> u32 {
    4096
}
/// Implements the extent step and keeps its validation and state transitions visible at the call site.
fn extent() -> u64 {
    DEFAULT_EXTENT_BYTES
}
/// Implements the validate create step and keeps its validation and state transitions visible at the call site.
pub fn validate_create(v: &VolumeCreate) -> Result<()> {
    if v.size_bytes == 0 {
        bail!("volume size must be non-zero")
    }
    if !v.logical_block_bytes.is_power_of_two()
        || v.logical_block_bytes < 512
        || v.logical_block_bytes > 65536
    {
        bail!("logical_block_bytes must be a power of two from 512 through 65536")
    }
    if v.extent_bytes == 0 || !v.extent_bytes.is_multiple_of(v.logical_block_bytes as u64) {
        bail!("extent_bytes must be a multiple of logical_block_bytes")
    }
    Ok(())
}
/// Implements the validate io step and keeps its validation and state transitions visible at the call site.
pub fn validate_io(v: &VolumeRecord, offset: u64, len: u64) -> Result<()> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("I/O range overflow"))?;
    if end > v.size_bytes {
        bail!("I/O beyond end of volume")
    }
    Ok(())
}
/// Implements the extent key step and keeps its validation and state transitions visible at the call site.
pub fn extent_key(id: &str, n: u64) -> String {
    format!(".__keyspace/volumes/{id}/extents/{n:016x}")
}
/// Implements the read range step and keeps its validation and state transitions visible at the call site.
pub async fn read_range(
    st: &ClusterState,
    v: &VolumeRecord,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>> {
    validate_io(v, offset, len)?;
    let mut out = vec![0u8; len as usize];
    if len == 0 {
        return Ok(out);
    }
    let first = offset / v.extent_bytes;
    let last = (offset + len - 1) / v.extent_bytes;
    for n in first..=last {
        let Some(e) = v.extents.get(&n) else { continue };
        let data = get_object_version(st, &e.manifest).await?;
        let es = n * v.extent_bytes;
        let from = offset.max(es);
        let to = (offset + len).min(es + v.extent_bytes);
        let src = (from - es) as usize;
        let dst = (from - offset) as usize;
        let count = (to - from) as usize;
        if src + count <= data.len() {
            out[dst..dst + count].copy_from_slice(&data[src..src + count]);
        }
    }
    Ok(out)
}
/// Implements the stage write step and keeps its validation and state transitions visible at the call site.
pub async fn stage_write(
    st: &ClusterState,
    v: &VolumeRecord,
    offset: u64,
    data: &[u8],
    generation: u64,
) -> Result<Vec<VolumeExtent>> {
    validate_io(v, offset, data.len() as u64)?;
    if v.read_only {
        bail!("volume is read-only")
    }
    if data.is_empty() {
        return Ok(vec![]);
    }
    let first = offset / v.extent_bytes;
    let last = (offset + data.len() as u64 - 1) / v.extent_bytes;
    let mut out = Vec::new();
    for n in first..=last {
        let es = n * v.extent_bytes;
        let valid = ((v.size_bytes - es).min(v.extent_bytes)) as usize;
        let mut buf = if let Some(old) = v.extents.get(&n) {
            let mut x = get_object_version(st, &old.manifest).await?;
            x.resize(valid, 0);
            x
        } else {
            vec![0u8; valid]
        };
        let from = offset.max(es);
        let to = (offset + data.len() as u64).min(es + valid as u64);
        let src = (from - offset) as usize;
        let dst = (from - es) as usize;
        let count = (to - from) as usize;
        buf[dst..dst + count].copy_from_slice(&data[src..src + count]);
        let m = put_object(st, &extent_key(&v.id, n), &buf).await?;
        out.push(VolumeExtent {
            extent: n,
            manifest: m,
            generation,
        });
    }
    Ok(out)
}
/// Stage SCSI UNMAP/TRIM. Whole covered extents become holes; partial extents are
/// rewritten with zeroes. The caller atomically commits `remove` + `replace`.
pub async fn stage_unmap(
    st: &ClusterState,
    v: &VolumeRecord,
    offset: u64,
    len: u64,
    generation: u64,
) -> Result<(Vec<u64>, Vec<VolumeExtent>)> {
    validate_io(v, offset, len)?;
    if v.read_only {
        bail!("volume is read-only")
    }
    if len == 0 {
        return Ok((vec![], vec![]));
    }
    let first = offset / v.extent_bytes;
    let last = (offset + len - 1) / v.extent_bytes;
    let mut remove = Vec::new();
    let mut replace = Vec::new();
    for n in first..=last {
        let es = n * v.extent_bytes;
        let ee = (es + v.extent_bytes).min(v.size_bytes);
        let from = offset.max(es);
        let to = (offset + len).min(ee);
        if from == es && to == ee {
            if v.extents.contains_key(&n) {
                remove.push(n);
            }
            continue;
        }
        if let Some(old) = v.extents.get(&n) {
            let valid = (ee - es) as usize;
            let mut buf = get_object_version(st, &old.manifest).await?;
            buf.resize(valid, 0);
            buf[(from - es) as usize..(to - es) as usize].fill(0);
            if buf.iter().all(|x| *x == 0) {
                remove.push(n)
            } else {
                let m = put_object(st, &extent_key(&v.id, n), &buf).await?;
                replace.push(VolumeExtent {
                    extent: n,
                    manifest: m,
                    generation,
                });
            }
        }
    }
    Ok((remove, replace))
}
/// Implements the make scsi identity step and keeps its validation and state transitions visible at the call site.
pub fn make_scsi_identity(id: &str) -> ScsiIdentity {
    let h = blake3::hash(id.as_bytes());
    let hx = h.to_hex().to_string();
    ScsiIdentity {
        vendor: "KAGI".into(),
        product: "KAGI ZVOL".into(),
        revision: "0026".into(),
        serial: hx[..20].to_uppercase(),
        naa: format!("6{}", &hx[..15]),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pr_register_reserve_and_release() {
        let mut pr = PersistentReservation::default();
        apply_pr_out(
            &mut pr,
            &PrOut::Register {
                initiator: "node-a".into(),
                current_key: 0,
                new_key: 0x11,
                aptpl: true,
                ignore_existing: false,
            },
        )
        .unwrap();
        apply_pr_out(
            &mut pr,
            &PrOut::Reserve {
                initiator: "node-a".into(),
                key: 0x11,
                reservation_type: PrType::WriteExclusive,
            },
        )
        .unwrap();
        assert!(pr_allows_write(&pr, Some("node-a")));
        assert!(!pr_allows_write(&pr, Some("node-b")));
        assert!(pr_allows_read(&pr, Some("node-b")));
        apply_pr_out(
            &mut pr,
            &PrOut::Release {
                initiator: "node-a".into(),
                key: 0x11,
                reservation_type: PrType::WriteExclusive,
            },
        )
        .unwrap();
        assert!(pr.reservation.is_none());
    }
    #[test]
    fn pr_key_mismatch_is_rejected() {
        let mut pr = PersistentReservation::default();
        apply_pr_out(
            &mut pr,
            &PrOut::Register {
                initiator: "node-a".into(),
                current_key: 0,
                new_key: 7,
                aptpl: false,
                ignore_existing: false,
            },
        )
        .unwrap();
        assert!(apply_pr_out(
            &mut pr,
            &PrOut::Register {
                initiator: "node-a".into(),
                current_key: 8,
                new_key: 9,
                aptpl: false,
                ignore_existing: false
            }
        )
        .is_err());
    }
    #[test]
    fn preempt_transfers_reservation() {
        let mut pr = PersistentReservation::default();
        for (i, k) in [("a", 1), ("b", 2)] {
            apply_pr_out(
                &mut pr,
                &PrOut::Register {
                    initiator: i.into(),
                    current_key: 0,
                    new_key: k,
                    aptpl: false,
                    ignore_existing: false,
                },
            )
            .unwrap();
        }
        apply_pr_out(
            &mut pr,
            &PrOut::Reserve {
                initiator: "a".into(),
                key: 1,
                reservation_type: PrType::ExclusiveAccess,
            },
        )
        .unwrap();
        apply_pr_out(
            &mut pr,
            &PrOut::Preempt {
                initiator: "b".into(),
                key: 2,
                service_action_key: 1,
                reservation_type: PrType::ExclusiveAccess,
                abort: true,
            },
        )
        .unwrap();
        assert_eq!(pr.reservation.as_ref().unwrap().holder, "b");
        assert!(!pr.registrations.contains_key("a"));
    }
    #[test]
    fn volume_validation_rejects_bad_geometry() {
        let mut v = VolumeCreate {
            id: None,
            name: "v".into(),
            size_bytes: 1024 * 1024,
            logical_block_bytes: 4096,
            extent_bytes: 4 * 1024 * 1024,
            thin_provisioned: true,
            presentations: vec![],
        };
        assert!(validate_create(&v).is_ok());
        v.logical_block_bytes = 1000;
        assert!(validate_create(&v).is_err());
    }
    #[test]
    fn scsi_identity_is_stable() {
        assert_eq!(
            make_scsi_identity("vol-1").serial,
            make_scsi_identity("vol-1").serial
        );
        assert_ne!(
            make_scsi_identity("vol-1").serial,
            make_scsi_identity("vol-2").serial
        );
    }
}
