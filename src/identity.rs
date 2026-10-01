// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Native NSS identity resolution. LDAP/AD/Kerberos principal mapping follows
//! the host's NSS/SSSD/winbind configuration; this is not password authentication.
use anyhow::{bail, Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ResolvedIdentity {
    pub user: String,
    pub uid: String,
    pub gids: Vec<String>,
    pub ad_sid: Option<String>,
    pub ad_group_sids: Vec<String>,
}

#[cfg(unix)]
fn resolve_nss(user: &str) -> Result<ResolvedIdentity> {
    use std::ffi::{CStr, CString};
    if user.is_empty() || user.len() > 1024 || user.chars().any(char::is_control) {
        bail!("invalid directory identity")
    }
    let name = CString::new(user)?;
    let mut size = 4096;
    loop {
        let mut buffer = vec![0u8; size];
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: name is NUL-terminated; record and buffer are writable for the
        // supplied lengths. NSS pointers are only read while buffer remains live.
        let status = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && size < 1024 * 1024 {
            size *= 2;
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if found.is_null() {
            bail!("identity not found")
        }
        // SAFETY: successful non-null getpwnam_r initialized record and pw_name.
        let record = unsafe { record.assume_init() };
        let canonical = unsafe { CStr::from_ptr(record.pw_name) }
            .to_str()?
            .to_owned();
        let canonical_c = CString::new(canonical.as_str())?;
        let mut count: libc::c_int = 32;
        let mut groups = vec![0 as libc::gid_t; count as usize];
        loop {
            // SAFETY: groups has count writable entries. A short buffer is
            // reported through count and retried with a bounded allocation.
            let result = unsafe {
                libc::getgrouplist(
                    canonical_c.as_ptr(),
                    record.pw_gid,
                    groups.as_mut_ptr(),
                    &mut count,
                )
            };
            if result >= 0 {
                break;
            }
            if count <= 0 || count as usize <= groups.len() || count > 65536 {
                bail!("directory group lookup failed or exceeded bound")
            }
            groups.resize(count as usize, 0);
        }
        groups.truncate(count as usize);
        groups.push(record.pw_gid);
        groups.sort_unstable();
        groups.dedup();
        return Ok(ResolvedIdentity {
            user: canonical,
            uid: record.pw_uid.to_string(),
            gids: groups.into_iter().map(|g| g.to_string()).collect(),
            ad_sid: None,
            ad_group_sids: vec![],
        });
    }
}
#[cfg(not(unix))]
fn resolve_nss(_: &str) -> Result<ResolvedIdentity> {
    bail!("native NSS resolution requires Unix")
}

fn valid_sid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return false;
    };
    let pieces: Vec<_> = rest.split('-').collect();
    (2..=16).contains(&pieces.len())
        && pieces
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u64>().is_ok())
}
async fn winbind(args: &[&str]) -> Result<String> {
    let mut command = tokio::process::Command::new("wbinfo");
    command.args(args).kill_on_drop(true);
    let output =
        tokio::time::timeout(std::time::Duration::from_secs(3), command.output()).await??;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        bail!("winbind lookup failed")
    }
    Ok(String::from_utf8(output.stdout)?)
}
/// Resolve Unix and supplementary group principals through the configured
/// directory provider. Missing optional winbind support does not erase NSS IDs.
pub async fn resolve(user: String) -> Result<ResolvedIdentity> {
    // Bound concurrent blocking NSS calls; timed-out tasks retain their permit
    // until the host resolver returns, preventing unbounded detached workers.
    static LIMIT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    let semaphore = LIMIT
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(8)))
        .clone();
    let permit = semaphore
        .try_acquire_owned()
        .context("identity resolver busy")?;
    let mut identity = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            resolve_nss(&user)
        }),
    )
    .await???;
    // --option=value prevents names beginning with '-' from becoming options.
    if let Ok(output) = winbind(&[&format!("--name-to-sid={}", identity.user)]).await {
        if let Some(sid) = output.split_whitespace().next().filter(|s| valid_sid(s)) {
            identity.ad_sid = Some(sid.to_owned());
            if let Ok(groups) = winbind(&[&format!("--user-sids={sid}")]).await {
                identity.ad_group_sids = groups
                    .lines()
                    .map(str::trim)
                    .filter(|s| valid_sid(s) && *s != sid)
                    .map(str::to_owned)
                    .collect();
                identity.ad_group_sids.sort();
                identity.ad_group_sids.dedup();
            }
        }
    }
    Ok(identity)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_names_and_sids() {
        assert!(resolve_nss("").is_err());
        assert!(resolve_nss("user\0other").is_err());
        assert!(valid_sid("S-1-5-21-123-456-789-1000"));
        assert!(!valid_sid("S-1-5-21;echo forged"));
        assert!(!valid_sid("S-1-5--1"));
    }
    #[cfg(unix)]
    #[test]
    fn native_local_identity_includes_primary_group() {
        let root = resolve_nss("root").unwrap();
        assert_eq!(root.uid, "0");
        assert!(root.gids.iter().any(|g| g == "0"));
    }
}

#[cfg(test)]
mod directory_execution_tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires a configured NSS directory provider and explicit expected identity"]
    async fn directory_provider_matches_expected_user_and_groups() {
        let user = std::env::var("KAGI_DIRECTORY_TEST_USER").expect("directory test user");
        let uid = std::env::var("KAGI_DIRECTORY_EXPECT_UID").expect("expected UID");
        let groups =
            std::env::var("KAGI_DIRECTORY_EXPECT_GIDS").expect("expected supplementary groups");
        let identity = resolve(user).await.unwrap();
        assert_eq!(identity.uid, uid);
        for group in groups.split(',') {
            assert!(identity.gids.iter().any(|g| g == group));
        }
        if let Ok(sid) = std::env::var("KAGI_DIRECTORY_EXPECT_SID") {
            assert_eq!(identity.ad_sid.as_deref(), Some(sid.as_str()));
        }
        if let Ok(sids) = std::env::var("KAGI_DIRECTORY_EXPECT_GROUP_SIDS") {
            for sid in sids.split(',') {
                assert!(identity.ad_group_sids.iter().any(|s| s == sid));
            }
        }
    }
}
