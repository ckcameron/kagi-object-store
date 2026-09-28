//! Kagi access policy and asynchronous side actions.
//!
//! Logical rules add restrictions to existing ACL/WORM checks. They never grant an
//! ACL permission. Kernel rules use the uploaded fileguard inode matcher; logical
//! objects require this separate gate because one object spans multiple fragments.
use crate::monitoring::Monitor;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

#[path = "../security/kagi-guard-common/src/types.rs"]
#[allow(dead_code)]
pub mod common;

/// Startup-only policy. No HTTP request may supply a command or change these rules.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub kernel: KernelConfig,
    #[serde(default)]
    pub objects: Vec<ObjectRule>,
    #[serde(default)]
    pub actions: BTreeMap<String, Action>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
/// Optional kernel enforcement; enabled configurations must attach successfully.
pub struct KernelConfig {
    #[serde(default)]
    pub enabled: bool,
    pub object: Option<PathBuf>,
    #[serde(default)]
    pub audit_only: bool,
    #[serde(default)]
    pub rules: Vec<FileRule>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(all(feature = "ebpf", target_os = "linux")), allow(dead_code))]
/// A single inode policy, optionally inherited by descendants of a directory.
pub struct FileRule {
    pub path: String,
    pub operations: Vec<String>,
    pub decision: Decision,
    #[serde(default)]
    pub recursive: bool,
    pub action: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// The access result, independent of whether a side action is also requested.
pub enum Decision {
    Allow,
    Deny,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// A logical namespace restriction, evaluated in addition to existing ACLs.
pub struct ObjectRule {
    /// Exact key or slash-delimited subtree. An empty prefix matches every object.
    pub key: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub privileged_only: bool,
    pub operations: Vec<String>,
    pub decision: Decision,
    pub action: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
/// Administrator-defined userspace work scheduled after the enforcement decision.
pub enum Action {
    Log,
    Exec {
        program: PathBuf,
        #[serde(default)]
        args: Vec<String>,
    },
    /// Only kernel events have an operating-system subject. Never signal an HTTP client.
    Signal {
        signal: i32,
    },
}

/// Immutable policy and a bounded side-action queue, shared by all request handlers.
#[derive(Clone)]
pub struct Security {
    pub config: Arc<Config>,
    pub monitor: Monitor,
    actions: tokio::sync::mpsc::Sender<(String, ActionContext)>,
}
#[derive(Clone, Debug, Default)]
/// Event facts available to argument templates; HTTP clients have no process identity.
pub struct ActionContext {
    pub path: String,
    pub operation: String,
    pub denied: bool,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
}

/// Keep operation aliases compatible with the uploaded fileguard configuration.
pub fn parse_operations(ops: &[String]) -> Result<u32> {
    use common::*;
    let mut mask = 0;
    for raw in ops {
        mask |= match raw.trim().to_ascii_lowercase().as_str() {
            "all" => OP_ALL,
            "open" => OP_OPEN,
            "read" => OP_READ,
            "write" => OP_WRITE,
            "append" => OP_APPEND,
            "exec" | "execute" => OP_EXEC,
            "getattr" | "stat" | "metadata" => OP_GETATTR,
            "create" | "mkdir" => OP_CREATE,
            "delete" | "unlink" | "rmdir" => OP_DELETE,
            "rename" | "move" => OP_RENAME,
            other => bail!("unknown security operation {other:?}"),
        };
    }
    if mask == 0 {
        bail!("security operation list may not be empty");
    }
    Ok(mask)
}

/// Validate even disabled rules so enabling enforcement cannot reinterpret bad policy.
pub fn validate(config: &Config) -> Result<()> {
    if config.kernel.rules.len() > 16384 {
        bail!("kernel policy limit is 16384 rules");
    }
    for rule in &config.kernel.rules {
        parse_operations(&rule.operations)?;
        if !std::path::Path::new(&rule.path).is_absolute() {
            bail!("kernel rule paths must be absolute");
        }
        validate_action(config, rule.action.as_deref(), false)?;
    }
    for rule in &config.objects {
        parse_operations(&rule.operations)?;
        validate_action(config, rule.action.as_deref(), true)?;
    }
    for action in config.actions.values() {
        match action {
            Action::Exec { program, args } => {
                if !program.is_absolute() || args.len() > 64 {
                    bail!("actions require an absolute executable and at most 64 arguments");
                }
            }
            Action::Signal { signal } if !(1..=64).contains(signal) => {
                bail!("signal must be in 1..=64")
            }
            _ => {}
        }
    }
    if config.kernel.enabled && config.kernel.object.is_none() {
        bail!("security.kernel.object is required when enabled");
    }
    Ok(())
}
/// Reject missing action names and signals without a trustworthy process subject.
fn validate_action(config: &Config, name: Option<&str>, logical: bool) -> Result<()> {
    if let Some(name) = name {
        let Some(action) = config.actions.get(name) else {
            bail!("unknown security action {name:?}");
        };
        if logical && matches!(action, Action::Signal { .. }) {
            bail!("signal actions require a kernel process identity");
        }
    }
    Ok(())
}

impl Security {
    /// Side effects run in a worker after policy evaluation, with a timeout and queue cap.
    pub fn new(config: Config, monitor: Monitor) -> Result<Self> {
        validate(&config)?;
        let config = Arc::new(config);
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<(String, ActionContext)>(256);
        let actions = config.clone();
        let events = monitor.clone();
        tokio::spawn(async move {
            while let Some((name, context)) = receiver.recv().await {
                let Some(action) = actions.actions.get(&name) else {
                    continue;
                };
                if let Err(error) = run_action(action, &context).await {
                    events.emit(
                        "error",
                        "security",
                        &context.path,
                        &format!("side action {name} failed: {error}"),
                    );
                }
            }
        });
        Ok(Self {
            config,
            monitor,
            actions: sender,
        })
    }

    /// All matching logical rules run; deny wins. Prefixes stop at slash boundaries.
    pub fn check(&self, key: &str, operation: u32, privileged: bool) -> bool {
        let mut allowed = true;
        for rule in &self.config.objects {
            if rule.privileged_only && !privileged {
                continue;
            }
            if !key_matches(&rule.key, key, rule.recursive) {
                continue;
            }
            if parse_operations(&rule.operations).unwrap_or(0) & operation == 0 {
                continue;
            }
            let denied = rule.decision == Decision::Deny;
            allowed &= !denied;
            self.record(
                rule.action.as_deref(),
                ActionContext {
                    path: key.into(),
                    operation: operation_name(operation),
                    denied,
                    ..Default::default()
                },
            );
        }
        allowed
    }

    /// Kernel denial is already final. Losing an event/action never changes that result.
    pub fn record(&self, action: Option<&str>, context: ActionContext) {
        self.monitor.emit(
            if context.denied { "warning" } else { "info" },
            "security",
            &context.path,
            &format!(
                "{} {} pid={} tgid={} uid={} gid={} comm={}",
                if context.denied { "deny" } else { "allow" },
                context.operation,
                context.pid,
                context.tgid,
                context.uid,
                context.gid,
                context.comm
            ),
        );
        if let Some(name) = action {
            if self
                .actions
                .try_send((name.into(), context.clone()))
                .is_err()
            {
                self.monitor.emit(
                    "error",
                    "security",
                    &context.path,
                    "side-action queue full or unavailable; action dropped",
                );
            }
        }
    }
}

/// Compare canonical boundary-separated keys without filesystem path resolution.
pub fn key_matches(rule: &str, key: &str, recursive: bool) -> bool {
    let rule = rule.trim_matches('/');
    let key = key.trim_matches('/');
    key == rule
        || recursive
            && (rule.is_empty() || key.strip_prefix(rule).is_some_and(|s| s.starts_with('/')))
}

/// Preserve combined masks such as read|write in telemetry and action arguments.
pub fn operation_name(mask: u32) -> String {
    let names = [
        (common::OP_OPEN, "open"),
        (common::OP_READ, "read"),
        (common::OP_WRITE, "write"),
        (common::OP_APPEND, "append"),
        (common::OP_EXEC, "exec"),
        (common::OP_GETATTR, "getattr"),
        (common::OP_CREATE, "create"),
        (common::OP_DELETE, "delete"),
        (common::OP_RENAME, "rename"),
    ];
    names
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

/// Substitute whole argument values without invoking a shell or reinterpreting placeholders.
fn render_arg(arg: &str, context: &ActionContext) -> String {
    let values = [
        ("path", context.path.clone()),
        ("operation", context.operation.clone()),
        (
            "decision",
            if context.denied { "deny" } else { "allow" }.into(),
        ),
        ("pid", context.pid.to_string()),
        ("tgid", context.tgid.to_string()),
        ("uid", context.uid.to_string()),
        ("gid", context.gid.to_string()),
        ("comm", context.comm.clone()),
    ];
    let mut output = String::new();
    let mut rest = arg;
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        rest = &rest[start..];
        if let Some(end) = rest.find('}') {
            if let Some((_, value)) = values.iter().find(|(name, _)| *name == &rest[1..end]) {
                output.push_str(value);
            } else {
                output.push_str(&rest[..=end]);
            }
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    output.push_str(rest);
    output
}

/// Reap command children and surface failures without altering the original decision.
async fn run_action(action: &Action, context: &ActionContext) -> Result<()> {
    match action {
        Action::Log => Ok(()),
        Action::Exec { program, args } => {
            let mut child = tokio::process::Command::new(program)
                .args(args.iter().map(|s| render_arg(s, context)))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let status = tokio::time::timeout(Duration::from_secs(30), child.wait()).await??;
            if !status.success() {
                bail!("executable exited with {status}");
            }
            Ok(())
        }
        Action::Signal { signal } => {
            if context.tgid <= 1 {
                bail!("refusing signal without a valid kernel subject");
            }
            // Preserve fileguard's asynchronous TGID semantics; PID reuse is documented.
            let status = tokio::process::Command::new("/bin/kill")
                .args([format!("-{signal}"), context.tgid.to_string()])
                .status()
                .await?;
            if !status.success() {
                bail!("signal delivery failed");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subtree_boundary_and_literal_arguments() {
        assert!(key_matches("secret", "secret/a", true));
        assert!(!key_matches("secret", "secretary/a", true));
        let c = ActionContext {
            path: "{uid};$(echo bad)".into(),
            uid: 42,
            ..Default::default()
        };
        assert_eq!(render_arg("{path} {uid}", &c), "{uid};$(echo bad) 42");
    }
    #[tokio::test]
    async fn deny_wins_and_privileged_rules_are_selective() {
        let cfg: Config = serde_yaml::from_str("objects:\n - {key: secret, recursive: true, operations: [all], decision: allow}\n - {key: secret, recursive: true, operations: [write], decision: deny, privileged_only: true}\n").unwrap();
        let security = Security::new(cfg, Monitor::new(16)).unwrap();
        assert!(security.check("secret/a", common::OP_READ, true));
        assert!(security.check("secret/a", common::OP_WRITE, false));
        assert!(!security.check("secret/a", common::OP_WRITE, true));
    }
}

#[cfg(test)]
mod action_tests {
    use super::*;
    #[tokio::test]
    async fn allow_and_deny_both_deliver_configured_actions() {
        let root = std::env::temp_dir().join(format!("kagi-action-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        for (index, decision) in [Decision::Allow, Decision::Deny].iter().enumerate() {
            let marker = root.join(index.to_string());
            let config = Config {
                objects: vec![ObjectRule {
                    key: "key".into(),
                    recursive: false,
                    privileged_only: false,
                    operations: vec!["read".into()],
                    decision: *decision,
                    action: Some("record".into()),
                }],
                actions: BTreeMap::from([(
                    "record".into(),
                    Action::Exec {
                        program: PathBuf::from("/usr/bin/touch"),
                        args: vec![marker.to_string_lossy().into_owned()],
                    },
                )]),
                ..Default::default()
            };
            let security = Security::new(config, Monitor::new(16)).unwrap();
            assert_eq!(
                security.check("key", common::OP_READ, false),
                *decision == Decision::Allow
            );
            tokio::time::timeout(Duration::from_secs(3), async {
                while !marker.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn invalid_actions_and_operations_fail_closed() {
        let bad: Config = serde_yaml::from_str(
            "objects: [{key: x, operations: [read], decision: deny, action: unknown}]",
        )
        .unwrap();
        assert!(validate(&bad).is_err());
        assert!(parse_operations(&["typo".into()]).is_err());
        assert!(parse_operations(&[]).is_err());
        let signal: Config = serde_yaml::from_str("objects: [{key: x, operations: [read], decision: deny, action: kill}]\nactions: {kill: {type: signal, signal: 9}}").unwrap();
        assert!(validate(&signal).is_err());
    }
}
