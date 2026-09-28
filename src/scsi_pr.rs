// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Kagi SCSI-3 persistent-reservation wire handling.
//!
//! This module decodes PR IN/OUT commands, validates service actions, updates the replicated
//! reservation model, and produces standards-shaped response payloads. The decoder keeps
//! wire-format handling separate from the higher-level reservation policy in `block.rs`.

// SPC-3/4 Persistent Reservation CDB decoding/encoding helpers.
//! SPC-3/4 Persistent Reservation wire helpers for target frontends.
//! This module deliberately contains no transport code: virtio-scsi, iSCSI/TCMU,
//! or another SCSI target maps CDBs to these operations and commits them through Raft.
use crate::block::{PrIn, PrOut, PrType};
use anyhow::{bail, Result};
pub const OP_PERSISTENT_RESERVE_IN: u8 = 0x5e;
pub const OP_PERSISTENT_RESERVE_OUT: u8 = 0x5f;
/// Implements the type from code step and keeps its validation and state transitions visible at the call site.
pub fn type_from_code(c: u8) -> Result<PrType> {
    Ok(match c & 0x0f {
        1 => PrType::WriteExclusive,
        3 => PrType::ExclusiveAccess,
        5 => PrType::WriteExclusiveRegistrantsOnly,
        6 => PrType::ExclusiveAccessRegistrantsOnly,
        7 => PrType::WriteExclusiveAllRegistrants,
        8 => PrType::ExclusiveAccessAllRegistrants,
        _ => bail!("unsupported SCSI PR type {c:#x}"),
    })
}
/// Implements the type code step and keeps its validation and state transitions visible at the call site.
pub fn type_code(t: PrType) -> u8 {
    match t {
        PrType::WriteExclusive => 1,
        PrType::ExclusiveAccess => 3,
        PrType::WriteExclusiveRegistrantsOnly => 5,
        PrType::ExclusiveAccessRegistrantsOnly => 6,
        PrType::WriteExclusiveAllRegistrants => 7,
        PrType::ExclusiveAccessAllRegistrants => 8,
    }
}
/// Decode a PERSISTENT RESERVE OUT CDB and its parameter list.
///
/// SPC service actions do not all use the SCOPE/TYPE field in CDB byte 2.
/// REGISTER, CLEAR, and REGISTER AND IGNORE EXISTING KEY therefore accept the
/// required zero value without trying to interpret it as a reservation type.
/// RESERVE, RELEASE, PREEMPT, and PREEMPT AND ABORT require a supported type
/// and currently support logical-unit scope only.
///
/// `initiator` must be a stable transport identity (for example an iSCSI IQN,
/// FC WWPN, VM UUID, or another target-port/initiator nexus identifier).
pub fn decode_pr_out(cdb: &[u8], p: &[u8], initiator: &str) -> Result<PrOut> {
    if cdb.len() < 10 || cdb[0] != OP_PERSISTENT_RESERVE_OUT {
        bail!("not a PR OUT CDB")
    }
    if p.len() < 24 {
        bail!("PR OUT parameter list too short")
    }
    let service_action = cdb[1] & 0x1f;
    let reservation_key = u64::from_be_bytes(p[0..8].try_into()?);
    let service_action_key = u64::from_be_bytes(p[8..16].try_into()?);
    let aptpl = (p[20] & 1) != 0;
    // Only service actions that create/change a reservation consume SCOPE/TYPE.
    // Key-registration and CLEAR actions use byte 2 as a reserved zero field.
    let reservation_type = || -> Result<PrType> {
        let scope = (cdb[2] >> 4) & 0x0f;
        if scope != 0 {
            bail!("unsupported SCSI PR scope {scope:#x}; only logical-unit scope is supported")
        }
        type_from_code(cdb[2] & 0x0f)
    };
    Ok(match service_action {
        0 => PrOut::Register {
            initiator: initiator.into(),
            current_key: reservation_key,
            new_key: service_action_key,
            aptpl,
            ignore_existing: false,
        },
        1 => PrOut::Reserve {
            initiator: initiator.into(),
            key: reservation_key,
            reservation_type: reservation_type()?,
        },
        2 => PrOut::Release {
            initiator: initiator.into(),
            key: reservation_key,
            reservation_type: reservation_type()?,
        },
        3 => PrOut::Clear {
            initiator: initiator.into(),
            key: reservation_key,
        },
        4 => PrOut::Preempt {
            initiator: initiator.into(),
            key: reservation_key,
            service_action_key,
            reservation_type: reservation_type()?,
            abort: false,
        },
        5 => PrOut::Preempt {
            initiator: initiator.into(),
            key: reservation_key,
            service_action_key,
            reservation_type: reservation_type()?,
            abort: true,
        },
        6 => PrOut::Register {
            initiator: initiator.into(),
            current_key: 0,
            new_key: service_action_key,
            aptpl,
            ignore_existing: true,
        },
        _ => bail!("unsupported PR OUT service action {service_action}"),
    })
}
/// Encode PR IN READ KEYS (SA=0) or READ RESERVATION (SA=1).
pub fn encode_pr_in(cdb: &[u8], state: &PrIn) -> Result<Vec<u8>> {
    if cdb.len() < 10 || cdb[0] != OP_PERSISTENT_RESERVE_IN {
        bail!("not a PR IN CDB")
    }
    let sa = cdb[1] & 0x1f;
    let alloc = u16::from_be_bytes([cdb[7], cdb[8]]) as usize;
    let mut o = Vec::new();
    o.extend_from_slice(&(state.generation as u32).to_be_bytes());
    match sa {
        0 => {
            let n = (state.registrations.len() * 8) as u32;
            o.extend_from_slice(&n.to_be_bytes());
            for r in state.registrations.values() {
                o.extend_from_slice(&r.key.to_be_bytes());
            }
        }
        1 => {
            if let Some(r) = &state.reservation {
                o.extend_from_slice(&16u32.to_be_bytes());
                o.extend_from_slice(&r.key.to_be_bytes());
                o.extend_from_slice(&[0; 4]);
                o.push(0);
                o.push(type_code(r.reservation_type));
                o.extend_from_slice(&[0; 2]);
            } else {
                o.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        _ => bail!("unsupported PR IN service action {sa}"),
    };
    o.truncate(alloc.min(o.len()));
    Ok(o)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::PrRegistration;
    use std::collections::BTreeMap;
    fn pr_out_cdb(service_action: u8, scope_type: u8) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = OP_PERSISTENT_RESERVE_OUT;
        cdb[1] = service_action & 0x1f;
        cdb[2] = scope_type;
        cdb
    }
    fn pr_out_params(current_key: u64, new_key: u64) -> [u8; 24] {
        let mut p = [0u8; 24];
        p[0..8].copy_from_slice(&current_key.to_be_bytes());
        p[8..16].copy_from_slice(&new_key.to_be_bytes());
        p
    }
    #[test]
    fn type_code_round_trip() {
        for t in [
            PrType::WriteExclusive,
            PrType::ExclusiveAccess,
            PrType::WriteExclusiveRegistrantsOnly,
            PrType::ExclusiveAccessRegistrantsOnly,
            PrType::WriteExclusiveAllRegistrants,
            PrType::ExclusiveAccessAllRegistrants,
        ] {
            assert_eq!(type_from_code(type_code(t)).unwrap(), t);
        }
    }
    #[test]
    fn decode_register_accepts_reserved_zero_type() {
        let cdb = pr_out_cdb(0, 0);
        let p = pr_out_params(1, 2);
        let op = decode_pr_out(&cdb, &p, "iqn.test").unwrap();
        match op {
            PrOut::Register {
                initiator,
                current_key,
                new_key,
                ignore_existing,
                ..
            } => {
                assert_eq!(initiator, "iqn.test");
                assert_eq!(current_key, 1);
                assert_eq!(new_key, 2);
                assert!(!ignore_existing);
            }
            _ => panic!("wrong operation"),
        }
    }
    #[test]
    fn decode_register_ignore_existing_accepts_reserved_zero_type() {
        let cdb = pr_out_cdb(6, 0);
        let mut p = pr_out_params(0xdead_beef, 7);
        p[20] |= 1;
        // APTPL
        let op = decode_pr_out(&cdb, &p, "iqn.test").unwrap();
        match op {
            PrOut::Register {
                current_key,
                new_key,
                aptpl,
                ignore_existing,
                ..
            } => {
                assert_eq!(current_key, 0);
                assert_eq!(new_key, 7);
                assert!(aptpl);
                assert!(ignore_existing);
            }
            _ => panic!("wrong operation"),
        }
    }
    #[test]
    fn decode_clear_accepts_reserved_zero_type() {
        let cdb = pr_out_cdb(3, 0);
        let p = pr_out_params(0x1234, 0);
        let op = decode_pr_out(&cdb, &p, "iqn.clear").unwrap();
        match op {
            PrOut::Clear { initiator, key } => {
                assert_eq!(initiator, "iqn.clear");
                assert_eq!(key, 0x1234);
            }
            _ => panic!("wrong operation"),
        }
    }
    #[test]
    fn decode_reserve_requires_supported_type() {
        let bad = pr_out_cdb(1, 0);
        let p = pr_out_params(1, 0);
        assert!(decode_pr_out(&bad, &p, "iqn.test").is_err());
        let good = pr_out_cdb(1, type_code(PrType::WriteExclusive));
        let op = decode_pr_out(&good, &p, "iqn.test").unwrap();
        match op {
            PrOut::Reserve {
                key,
                reservation_type,
                ..
            } => {
                assert_eq!(key, 1);
                assert_eq!(reservation_type, PrType::WriteExclusive);
            }
            _ => panic!("wrong operation"),
        }
    }
    #[test]
    fn decode_preempt_and_abort_carries_type_and_keys() {
        let cdb = pr_out_cdb(5, type_code(PrType::ExclusiveAccessRegistrantsOnly));
        let p = pr_out_params(11, 22);
        let op = decode_pr_out(&cdb, &p, "iqn.preempt").unwrap();
        match op {
            PrOut::Preempt {
                key,
                service_action_key,
                reservation_type,
                abort,
                ..
            } => {
                assert_eq!(key, 11);
                assert_eq!(service_action_key, 22);
                assert_eq!(reservation_type, PrType::ExclusiveAccessRegistrantsOnly);
                assert!(abort);
            }
            _ => panic!("wrong operation"),
        }
    }
    #[test]
    fn decode_type_bearing_action_rejects_nonzero_scope() {
        let cdb = pr_out_cdb(1, 0x10 | type_code(PrType::WriteExclusive));
        let p = pr_out_params(1, 0);
        let err = decode_pr_out(&cdb, &p, "iqn.test").unwrap_err().to_string();
        assert!(err.contains("scope"));
    }
    #[test]
    fn unsupported_service_action_is_reported_before_reserved_type() {
        let cdb = pr_out_cdb(7, 0);
        let p = pr_out_params(1, 2);
        let err = decode_pr_out(&cdb, &p, "iqn.test").unwrap_err().to_string();
        assert!(err.contains("service action 7"));
    }
    #[test]
    fn encode_read_keys_contains_generation_and_keys() {
        let mut regs = BTreeMap::new();
        regs.insert(
            "a".into(),
            PrRegistration {
                key: 0x1122,
                aptpl: false,
                registered_at_unix_ms: 0,
            },
        );
        let state = PrIn {
            generation: 3,
            registrations: regs,
            reservation: None,
        };
        let mut cdb = [0u8; 10];
        cdb[0] = OP_PERSISTENT_RESERVE_IN;
        cdb[1] = 0x00;
        cdb[7..9].copy_from_slice(&64u16.to_be_bytes());
        let out = encode_pr_in(&cdb, &state).unwrap();
        assert_eq!(&out[0..4], &3u32.to_be_bytes());
        let key = 0x1122u64.to_be_bytes();
        assert!(out.windows(8).any(|w| w == key.as_slice()));
    }
}
