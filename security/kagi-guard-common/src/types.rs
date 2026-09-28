// SPDX-License-Identifier: MIT OR Apache-2.0
pub const OP_OPEN: u32 = 1 << 0;
pub const OP_READ: u32 = 1 << 1;
pub const OP_WRITE: u32 = 1 << 2;
pub const OP_APPEND: u32 = 1 << 3;
pub const OP_EXEC: u32 = 1 << 4;
pub const OP_GETATTR: u32 = 1 << 5;
pub const OP_CREATE: u32 = 1 << 6;
pub const OP_DELETE: u32 = 1 << 7;
pub const OP_RENAME: u32 = 1 << 8;

pub const OP_ALL: u32 = OP_OPEN
    | OP_READ
    | OP_WRITE
    | OP_APPEND
    | OP_EXEC
    | OP_GETATTR
    | OP_CREATE
    | OP_DELETE
    | OP_RENAME;

pub const POLICY_RECURSIVE: u32 = 1 << 0;

pub const EACCES: i32 = 13;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Hash)]
pub struct ObjectKey {
    pub dev: u64,
    pub ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Policy {
    /// Which operations cause a match/event.
    pub watch_mask: u32,
    /// Subset of watch_mask that is denied synchronously in the LSM hook.
    pub deny_mask: u32,
    pub flags: u32,
    pub rule_id: u32,
    pub action_id: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Event {
    pub timestamp_ns: u64,
    pub key: ObjectKey,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub operation: u32,
    pub denied: u32,
    pub rule_id: u32,
    pub action_id: u32,
    pub comm: [u8; 16],
}
