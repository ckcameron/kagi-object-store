// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Launch a process with explicit Linux scheduling before its worker threads start.
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use std::{ffi::OsString, process::Command};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Policy {
    Normal,
    RoundRobin,
    Fifo,
}
#[derive(Parser)]
#[command(
    name = "kagi-run",
    version,
    about = "Launch Kagi or another process with explicit scheduling"
)]
struct Args {
    #[arg(long, value_enum, default_value = "normal")]
    policy: Policy,
    /// Real-time priority (1–99); normal scheduling requires zero.
    #[arg(long, default_value_t = 0)]
    priority: i32,
    /// Logical CPUs to use, e.g. 2,3,4. Real-time mode must leave one allowed CPU free.
    #[arg(long, value_delimiter = ',')]
    cpus: Vec<usize>,
    /// Executable and arguments, after --. No shell expansion is performed.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}
fn validate(policy: Policy, priority: i32) -> Result<()> {
    if (policy == Policy::Normal && priority != 0)
        || (policy != Policy::Normal && !(1..=99).contains(&priority))
    {
        bail!("normal scheduling requires priority 0; real-time scheduling requires 1–99");
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn launch(args: Args) -> Result<()> {
    use std::os::unix::process::CommandExt;
    validate(args.policy, args.priority)?;
    // The launcher is single-threaded. Affinity and scheduling survive exec;
    // subsequently created Tokio and Rayon threads inherit both settings.
    let mut available: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&available), &mut available) } != 0
    {
        return Err(std::io::Error::last_os_error()).context("read allowed CPUs");
    }
    let allowed: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &available) })
        .collect();
    let realtime = args.policy != Policy::Normal;
    let selected = if args.cpus.is_empty() {
        if realtime {
            allowed.iter().skip(1).copied().collect()
        } else {
            allowed.clone()
        }
    } else {
        args.cpus.clone()
    };
    let selected: std::collections::BTreeSet<_> = selected.into_iter().collect();
    if selected.is_empty() || selected.iter().any(|cpu| !allowed.contains(cpu)) {
        bail!("CPU selection must be nonempty and inside this process's allowed CPU set");
    }
    if realtime && selected.len() >= allowed.len() {
        bail!("real-time mode must leave at least one allowed logical CPU outside its affinity");
    }
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &cpu in &selected {
        unsafe { libc::CPU_SET(cpu, &mut affinity) };
    }
    if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&affinity), &affinity) } != 0 {
        return Err(std::io::Error::last_os_error()).context("apply CPU affinity");
    }
    let policy = match args.policy {
        Policy::Normal => libc::SCHED_OTHER,
        Policy::RoundRobin => libc::SCHED_RR,
        Policy::Fifo => libc::SCHED_FIFO,
    };
    let parameters = libc::sched_param {
        sched_priority: args.priority,
    };
    if unsafe { libc::sched_setscheduler(0, policy, &parameters) } != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "requested scheduling was not applied; real-time requires an appropriate RLIMIT_RTPRIO or CAP_SYS_NICE; command was not started");
    }
    let mut actual: libc::sched_param = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getscheduler(0) } != policy
        || unsafe { libc::sched_getparam(0, &mut actual) } != 0
        || actual.sched_priority != args.priority
    {
        bail!("scheduler verification failed; command was not started");
    }
    eprintln!(
        "Applied {:?} scheduling, priority {}, logical CPUs {:?}",
        args.policy, actual.sched_priority, selected
    );
    Err(Command::new(&args.command[0])
        .args(&args.command[1..])
        .exec())
    .context("execute requested command")
}
fn main() -> Result<()> {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    {
        launch(args)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("kagi-run scheduling requires Linux")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_priority_contract() {
        assert!(validate(Policy::Normal, 0).is_ok());
        assert!(validate(Policy::Normal, 1).is_err());
        for policy in [Policy::RoundRobin, Policy::Fifo] {
            assert!(validate(policy, 0).is_err());
            assert!(validate(policy, 1).is_ok());
            assert!(validate(policy, 99).is_ok());
            assert!(validate(policy, 100).is_err());
        }
    }
}
