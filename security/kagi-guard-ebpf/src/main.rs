// Upstream package: MIT OR Apache-2.0; kernel license marker: Dual MIT/GPL.
// See THIRD-PARTY-NOTICES.md; these upstream declarations are preserved.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, Global,
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use kagi_guard_common::{
    EACCES, Event, OP_APPEND, OP_CREATE, OP_DELETE, OP_EXEC, OP_GETATTR, OP_OPEN, OP_READ,
    OP_RENAME, OP_WRITE, ObjectKey, POLICY_RECURSIVE, Policy,
};

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use vmlinux::{dentry, file, inode, linux_binprm};

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

const MAY_EXEC: i32 = 0x0000_0001;
const MAY_WRITE: i32 = 0x0000_0002;
const MAY_READ: i32 = 0x0000_0004;
const MAY_APPEND: i32 = 0x0000_0008;

/// Bounded recursive-directory walk. This does not cross a mount root because
/// d_parent points to itself at that boundary.
const MAX_ANCESTORS: usize = 32;

#[map]
static POLICIES: HashMap<ObjectKey, Policy> = HashMap::with_max_entries(16_384, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static LOST_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The userspace loader writes its own TGID here so the policy daemon does not
/// deadlock itself by touching watched configuration/log/executable files.
#[unsafe(no_mangle)]
static DAEMON_TGID: Global<u32> = Global::new(0);

#[derive(Clone, Copy)]
struct Match {
    key: ObjectKey,
    policy: Policy,
}

#[inline(always)]
fn prior_ret(ctx: &LsmContext, index: usize) -> i32 {
    unsafe { ctx.arg(index) }
}

#[inline(always)]
fn should_bypass(ctx: &LsmContext) -> bool {
    let daemon = DAEMON_TGID.load();
    daemon != 0 && ctx.tgid() == daemon
}

#[inline(always)]
unsafe fn key_from_inode(node: *const inode) -> Option<ObjectKey> {
    if node.is_null() {
        return None;
    }

    let sb = unsafe { (*node).i_sb };
    if sb.is_null() {
        return None;
    }

    // Kernel s_dev uses a 12-bit major and 20-bit minor. The Kagi loader
    // translates the different userspace stat encoding before inserting keys.
    let dev = unsafe { (*sb).s_dev as u64 };
    let ino = unsafe { (*node).i_ino as u64 };

    Some(ObjectKey { dev, ino })
}

#[inline(always)]
unsafe fn policy_for_inode(
    node: *const inode,
    operation: u32,
    require_recursive: bool,
) -> Option<Match> {
    let key = unsafe { key_from_inode(node) }?;
    let policy = unsafe { POLICIES.get(&key) }?;

    if policy.watch_mask & operation == 0 {
        return None;
    }
    if require_recursive && policy.flags & POLICY_RECURSIVE == 0 {
        return None;
    }

    Some(Match {
        key,
        policy: *policy,
    })
}

#[inline(always)]
unsafe fn match_dentry(mut dent: *const dentry, operation: u32) -> Option<Match> {
    if dent.is_null() {
        return None;
    }

    // Direct policy on the object.
    let node = unsafe { (*dent).d_inode };
    if let Some(m) = unsafe { policy_for_inode(node, operation, false) } {
        return Some(m);
    }

    // Recursive policies on ancestors.
    let mut n = 0usize;
    let mut parent = unsafe { (*dent).d_parent };
    while n < MAX_ANCESTORS {
        if parent.is_null() || parent == dent {
            break;
        }

        let parent_inode = unsafe { (*parent).d_inode };
        if let Some(m) = unsafe { policy_for_inode(parent_inode, operation, true) } {
            return Some(m);
        }

        let next = unsafe { (*parent).d_parent };
        dent = parent;
        parent = next;
        n += 1;
    }

    None
}

#[inline(always)]
fn emit(ctx: &LsmContext, matched: Match, operation: u32, denied: bool) {
    let comm = ctx.command().unwrap_or([0; 16]);
    let event = Event {
        timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        key: matched.key,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        gid: ctx.gid(),
        operation,
        denied: denied as u32,
        rule_id: matched.policy.rule_id,
        action_id: matched.policy.action_id,
        comm,
    };

    if EVENTS.output(&event, 0).is_err() {
        if let Some(counter) = LOST_EVENTS.get_ptr_mut(0) {
            unsafe {
                *counter = (*counter).wrapping_add(1);
            }
        }
    }
}

#[inline(always)]
unsafe fn enforce_dentry(ctx: &LsmContext, dent: *const dentry, operation: u32) -> i32 {
    let Some(matched) = (unsafe { match_dentry(dent, operation) }) else {
        return 0;
    };

    let denied = matched.policy.deny_mask & operation != 0;
    emit(ctx, matched, operation, denied);
    if denied { -EACCES } else { 0 }
}

#[inline(always)]
unsafe fn enforce_file(ctx: &LsmContext, fp: *const file, operation: u32) -> i32 {
    if fp.is_null() {
        return 0;
    }
    let dent = unsafe { (*fp).f_path.dentry };
    unsafe { enforce_dentry(ctx, dent, operation) }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 1);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let fp: *const file = unsafe { ctx.arg(0) };
    unsafe { enforce_file(&ctx, fp, OP_OPEN) }
}

#[lsm(hook = "file_permission")]
pub fn file_permission(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 2);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let fp: *const file = unsafe { ctx.arg(0) };
    let mask: i32 = unsafe { ctx.arg(1) };

    let mut operation = 0u32;
    if mask & MAY_READ != 0 {
        operation |= OP_READ;
    }
    if mask & MAY_WRITE != 0 {
        operation |= OP_WRITE;
    }
    if mask & MAY_APPEND != 0 {
        operation |= OP_APPEND;
    }
    if mask & MAY_EXEC != 0 {
        operation |= OP_EXEC;
    }

    if operation == 0 {
        return 0;
    }

    unsafe { enforce_file(&ctx, fp, operation) }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 1);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let bprm: *const linux_binprm = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return 0;
    }

    let fp = unsafe { (*bprm).file };
    unsafe { enforce_file(&ctx, fp, OP_EXEC) }
}

#[lsm(hook = "inode_getattr")]
pub fn inode_getattr(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 1);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let p: *const vmlinux::path = unsafe { ctx.arg(0) };
    if p.is_null() {
        return 0;
    }

    let dent = unsafe { (*p).dentry };
    unsafe { enforce_dentry(&ctx, dent, OP_GETATTR) }
}

#[lsm(hook = "inode_create")]
pub fn inode_create(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 3);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let new_dent: *const dentry = unsafe { ctx.arg(1) };
    if new_dent.is_null() {
        return 0;
    }

    let parent = unsafe { (*new_dent).d_parent };
    unsafe { enforce_dentry(&ctx, parent, OP_CREATE) }
}

#[lsm(hook = "inode_mkdir")]
pub fn inode_mkdir(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 3);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let new_dent: *const dentry = unsafe { ctx.arg(1) };
    if new_dent.is_null() {
        return 0;
    }

    let parent = unsafe { (*new_dent).d_parent };
    unsafe { enforce_dentry(&ctx, parent, OP_CREATE) }
}

#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 2);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let dent: *const dentry = unsafe { ctx.arg(1) };
    unsafe { enforce_dentry(&ctx, dent, OP_DELETE) }
}

#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 2);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let dent: *const dentry = unsafe { ctx.arg(1) };
    unsafe { enforce_dentry(&ctx, dent, OP_DELETE) }
}

#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    let ret = prior_ret(&ctx, 5);
    if ret != 0 || should_bypass(&ctx) {
        return ret;
    }

    let old_dent: *const dentry = unsafe { ctx.arg(1) };
    let new_dent: *const dentry = unsafe { ctx.arg(3) };

    let source = unsafe { enforce_dentry(&ctx, old_dent, OP_RENAME) };
    if source != 0 {
        return source;
    }

    if new_dent.is_null() {
        return 0;
    }

    // new_dentry can be negative, so mediate the destination directory.
    let dest_parent = unsafe { (*new_dent).d_parent };
    unsafe { enforce_dentry(&ctx, dest_parent, OP_RENAME) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
