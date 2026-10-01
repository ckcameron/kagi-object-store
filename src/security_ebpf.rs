// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Aya adapter for the supplied fileguard LSM implementation.
//!
//! Load every policy before attaching hooks. Keep the Ebpf owner alive for the entire
//! server lifetime: dropping it detaches the links. Startup errors are fatal whenever
//! kernel protection is enabled; Kagi never silently falls back to audit-only mode.
use crate::security::{
    self,
    common::{Event, ObjectKey, Policy, POLICY_RECURSIVE},
    ActionContext, Decision, Security,
};
use anyhow::{anyhow, bail, Context, Result};
use aya::{
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::Lsm,
    Btf, Ebpf, EbpfLoader, Pod,
};
use std::{collections::HashSet, os::unix::fs::MetadataExt};
use tokio::io::unix::AsyncFd;

// These are local repr(C), integer-only types shared verbatim with the BPF crate.
unsafe impl Pod for ObjectKey {}
unsafe impl Pod for Policy {}

/// Retain ownership of all attached links until server shutdown.
pub struct Guard {
    _ebpf: Ebpf,
    reader: tokio::task::JoinHandle<()>,
    loss_monitor: tokio::task::JoinHandle<()>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.reader.abort();
        self.loss_monitor.abort();
    }
}

/// Linux kernel dev_t uses 12 major bits and 20 minor bits; stat uses new_encode_dev.
/// Translating this is essential on devices whose minor number exceeds 255.
fn kernel_device(dev: u64) -> u64 {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
    (major << 20) | minor
}

/// Load policies, attach the original LSM hook set, and start bounded event delivery.
pub fn start(security: Security) -> Result<Guard> {
    let cfg = &security.config.kernel;
    let mut loader = EbpfLoader::new();
    let tgid = std::process::id();
    loader.override_global("DAEMON_TGID", &tgid, true);
    let mut ebpf = loader.load_file(cfg.object.as_ref().context("missing BPF object")?)?;
    let mut seen = HashSet::new();
    {
        let mut policies: HashMap<_, ObjectKey, Policy> = HashMap::try_from(
            ebpf.map_mut("POLICIES")
                .ok_or_else(|| anyhow!("POLICIES missing"))?,
        )?;
        for (index, rule) in cfg.rules.iter().enumerate() {
            let metadata = std::fs::metadata(&rule.path)
                .with_context(|| format!("stat policy path {}", rule.path))?;
            if rule.recursive && !metadata.is_dir() {
                bail!("recursive policy needs a directory: {}", rule.path);
            }
            let key = ObjectKey {
                dev: kernel_device(metadata.dev()),
                ino: metadata.ino(),
            };
            if !seen.insert(key) {
                bail!(
                    "duplicate inode policy (including hardlink alias): {}",
                    rule.path
                );
            }
            let watch_mask = security::parse_operations(&rule.operations)?;
            let policy = Policy {
                watch_mask,
                deny_mask: if cfg.audit_only || rule.decision == Decision::Allow {
                    0
                } else {
                    watch_mask
                },
                flags: if rule.recursive { POLICY_RECURSIVE } else { 0 },
                rule_id: index as u32 + 1,
                action_id: if rule.action.is_some() {
                    index as u32 + 1
                } else {
                    0
                },
                _pad: 0,
            };
            policies.insert(key, policy, 0)?;
        }
    }
    let btf = Btf::from_sys_fs().context("load kernel BTF")?;
    for hook in [
        "file_open",
        "file_permission",
        "bprm_check_security",
        "inode_getattr",
        "inode_create",
        "inode_mkdir",
        "inode_unlink",
        "inode_rmdir",
        "inode_rename",
    ] {
        let program: &mut Lsm = ebpf
            .program_mut(hook)
            .with_context(|| format!("missing LSM {hook}"))?
            .try_into()?;
        program
            .load(hook, &btf)
            .with_context(|| format!("load LSM {hook}"))?;
        program
            .attach()
            .with_context(|| format!("attach LSM {hook}"))?;
    }
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS missing")?)?;
    let mut ring = AsyncFd::new(ring)?;
    security
        .monitor
        .emit("info", "security", "kernel", "BPF LSM hooks attached");
    let lost: PerCpuArray<_, u64> = PerCpuArray::try_from(
        ebpf.take_map("LOST_EVENTS")
            .context("LOST_EVENTS missing; rebuild the Kagi BPF object")?,
    )?;
    let monitor = security.monitor.clone();
    let loss_monitor = tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut previous = 0u64;
        loop {
            timer.tick().await;
            match lost.get(&0, 0) {
                Ok(values) => {
                    let total: u64 = values.iter().copied().sum();
                    if total != previous {
                        monitor.emit("error", "security", "kernel", &format!("BPF ring buffer lost {} events; associated side actions were not delivered", total.saturating_sub(previous)));
                        previous = total;
                    }
                }
                Err(error) => {
                    monitor.emit(
                        "error",
                        "security",
                        "kernel",
                        &format!("cannot read BPF event-loss counter: {error}"),
                    );
                    return;
                }
            }
        }
    });
    let reader = tokio::spawn(async move {
        loop {
            let mut ready = match ring.readable_mut().await {
                Ok(ready) => ready,
                Err(error) => {
                    security.monitor.emit(
                        "error",
                        "security",
                        "kernel",
                        &format!("BPF event reader failed: {error}; enforcement remains attached"),
                    );
                    return;
                }
            };
            while let Some(item) = ready.get_inner_mut().next() {
                if item.len() != std::mem::size_of::<Event>() {
                    security
                        .monitor
                        .emit("error", "security", "kernel", "invalid BPF event size");
                    continue;
                }
                // Ring buffer records need not have Rust Event alignment.
                let event = unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<Event>()) };
                let Some(rule) = event
                    .rule_id
                    .checked_sub(1)
                    .and_then(|i| security.config.kernel.rules.get(i as usize))
                else {
                    continue;
                };
                let end = event
                    .comm
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(event.comm.len());
                security.record(
                    rule.action.as_deref(),
                    ActionContext {
                        path: rule.path.clone(),
                        operation: security::operation_name(event.operation),
                        denied: event.denied != 0,
                        pid: event.pid,
                        tgid: event.tgid,
                        uid: event.uid,
                        gid: event.gid,
                        comm: String::from_utf8_lossy(&event.comm[..end]).into_owned(),
                    },
                );
            }
            ready.clear_ready();
        }
    });
    Ok(Guard {
        _ebpf: ebpf,
        reader,
        loss_monitor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_encoding_matches_kernel() {
        assert_eq!(kernel_device(0x801), (8 << 20) | 1);
        assert_eq!(kernel_device(0x100803), (8 << 20) | 259);
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    /// Run only on a disposable privileged runner with BPF LSM enabled. Missing
    /// bindings, attachment, deny enforcement or side-action delivery is failure.
    #[tokio::test]
    #[ignore = "requires privileged BPF LSM runner and KAGI_EBPF_OBJECT"]
    async fn kernel_allow_deny_and_side_action_execute() {
        let object = std::env::var_os("KAGI_EBPF_OBJECT").expect("set KAGI_EBPF_OBJECT");
        let root = std::env::temp_dir().join(format!("kagi-lsm-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let denied = root.join("denied");
        let allowed = root.join("allowed");
        let marker = root.join("action");
        std::fs::write(&denied, b"secret").unwrap();
        std::fs::write(&allowed, b"public").unwrap();
        let monitor = crate::monitoring::Monitor::new(32);
        let mut config = security::Config {
            kernel: security::KernelConfig {
                enabled: true,
                object: Some(object.into()),
                audit_only: false,
                rules: vec![security::FileRule {
                    path: denied.to_string_lossy().into_owned(),
                    operations: vec!["open".into(), "read".into()],
                    decision: Decision::Deny,
                    recursive: false,
                    action: Some("mark".into()),
                }],
            },
            ..Default::default()
        };
        config.actions.insert(
            "mark".into(),
            security::Action::Exec {
                program: "/usr/bin/touch".into(),
                args: vec![marker.to_string_lossy().into_owned()],
            },
        );
        let guard = start(Security::new(config, monitor).unwrap()).unwrap();
        let output = tokio::process::Command::new("/bin/cat")
            .arg(&allowed)
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"public");
        let output = tokio::process::Command::new("/bin/cat")
            .arg(&denied)
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("kernel event side action was not delivered");
        drop(guard);
        assert!(tokio::process::Command::new("/bin/cat")
            .arg(&denied)
            .output()
            .await
            .unwrap()
            .status
            .success());
        std::fs::remove_dir_all(root).unwrap();
    }
}
