//! Username / UID / GID lookups and group-membership queries.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use nix::unistd::{Gid, Group, Uid, User};

use crate::errors::{PmError, Result};

// ── UID / GID name cache ───────────────────────────────────────────────
//
// `uid_to_name` / `gid_to_name` are called once per file in scan paths
// (audit, find-orphans, tree). Each call opens /etc/passwd or /etc/group
// and scans linearly — O(files × entries) total. Strace on 15k files:
// 18 109 open("/etc/passwd") syscalls.
//
// We memoise by numeric id. Mutex-wrapped so a future rayon walker is
// safe without refactor. `Option<String>` so "unknown uid" is also
// cached (avoids repeated misses on orphan datasets).
static UID_CACHE: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();
static GID_CACHE: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();

fn uid_cache() -> &'static Mutex<HashMap<u32, Option<String>>> {
    UID_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn gid_cache() -> &'static Mutex<HashMap<u32, Option<String>>> {
    GID_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn lookup_user(name: &str) -> Result<User> {
    User::from_name(name)
        .map_err(|e| PmError::Other(format!("user lookup failed: {e}")))?
        .ok_or_else(|| PmError::UserNotFound(name.to_string()))
}

pub fn lookup_group(name: &str) -> Result<Group> {
    Group::from_name(name)
        .map_err(|e| PmError::Other(format!("group lookup failed: {e}")))?
        .ok_or_else(|| PmError::GroupNotFound(name.to_string()))
}

pub fn group_exists(name: &str) -> bool {
    matches!(Group::from_name(name), Ok(Some(_)))
}

pub fn user_in_group(user: &str, group: &str) -> bool {
    let g = match Group::from_name(group) {
        Ok(Some(g)) => g,
        _ => return false,
    };
    // Check supplementary membership.
    if g.mem.iter().any(|m| m == user) {
        return true;
    }
    // Check primary group.
    let u = match User::from_name(user) {
        Ok(Some(u)) => u,
        _ => return false,
    };
    u.gid == g.gid
}

/// All group IDs (primary + supplementary) for a user.
pub fn user_gids(username: &str) -> Result<std::collections::HashSet<Gid>> {
    let u = lookup_user(username)?;
    let mut gids = std::collections::HashSet::new();
    gids.insert(u.gid);
    // Scan all groups; on typical systems this is fine (<hundreds).
    if let Ok(groups) = nix::unistd::Group::from_name("") {
        // nix doesn't have getgrall(); we do a fallback via libc.
        let _ = groups;
    }
    // Use libc getgrouplist via a manual approach.
    gids.extend(supplementary_gids(username, u.gid)?);
    Ok(gids)
}

/// Get supplementary group IDs for a user via libc.
fn supplementary_gids(username: &str, primary_gid: Gid) -> Result<Vec<Gid>> {
    use std::ffi::CString;
    let c_user = CString::new(username).map_err(|_| PmError::Other("invalid username".into()))?;
    let mut ngroups: libc::c_int = 64;
    let mut groups: Vec<libc::gid_t> = vec![0; ngroups as usize];
    unsafe {
        let ret = libc::getgrouplist(
            c_user.as_ptr(),
            primary_gid.as_raw(),
            groups.as_mut_ptr(),
            &mut ngroups,
        );
        if ret == -1 {
            // ngroups now contains the required size.
            groups.resize(ngroups as usize, 0);
            libc::getgrouplist(
                c_user.as_ptr(),
                primary_gid.as_raw(),
                groups.as_mut_ptr(),
                &mut ngroups,
            );
        }
    }
    groups.truncate(ngroups as usize);
    Ok(groups.into_iter().map(Gid::from_raw).collect())
}

/// Resolve a uid to a username, fallback to numeric string.
///
/// Cached: each unique uid triggers at most one `getpwuid` syscall.
pub fn uid_to_name(uid: Uid) -> String {
    let raw = uid.as_raw();
    let mut cache = uid_cache().lock().unwrap();
    cache
        .entry(raw)
        .or_insert_with(|| User::from_uid(uid).ok().flatten().map(|u| u.name))
        .clone()
        .unwrap_or_else(|| raw.to_string())
}

/// Resolve a gid to a group name, fallback to numeric string.
///
/// Cached: each unique gid triggers at most one `getgrgid` syscall.
pub fn gid_to_name(gid: Gid) -> String {
    let raw = gid.as_raw();
    let mut cache = gid_cache().lock().unwrap();
    cache
        .entry(raw)
        .or_insert_with(|| Group::from_gid(gid).ok().flatten().map(|g| g.name))
        .clone()
        .unwrap_or_else(|| raw.to_string())
}

/// Does a user with this uid exist in /etc/passwd (or NSS)?
///
/// Shares the UID_CACHE with `uid_to_name` — the first call fills the
/// slot, every subsequent call for the same uid is a HashMap hit. On a
/// `/` walk where 99 % of inodes are owned by root this cuts the
/// per-inode cost from a `getpwuid` syscall to an atomic lock + lookup.
pub fn uid_exists(uid: Uid) -> bool {
    let raw = uid.as_raw();
    let mut cache = uid_cache().lock().unwrap();
    cache
        .entry(raw)
        .or_insert_with(|| User::from_uid(uid).ok().flatten().map(|u| u.name))
        .is_some()
}

/// Does a group with this gid exist in /etc/group (or NSS)?
/// See `uid_exists` for semantics.
pub fn gid_exists(gid: Gid) -> bool {
    let raw = gid.as_raw();
    let mut cache = gid_cache().lock().unwrap();
    cache
        .entry(raw)
        .or_insert_with(|| Group::from_gid(gid).ok().flatten().map(|g| g.name))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repeated lookups for the same uid must not perform repeated
    /// `getpwuid` calls. We can't strace from inside a test, but we can
    /// verify the cache is populated after the first call.
    #[test]
    fn uid_cache_memoises_unknown_ids() {
        // 999_999 is extremely unlikely to exist on a CI box; even if
        // it does, the behaviour still proves memoisation.
        let raw = 999_999u32;
        let _ = uid_to_name(Uid::from_raw(raw));
        let cache = uid_cache().lock().unwrap();
        assert!(cache.contains_key(&raw), "uid cache should be populated");
    }

    #[test]
    fn uid_cache_returns_consistent_value() {
        let raw = 999_998u32;
        let a = uid_to_name(Uid::from_raw(raw));
        let b = uid_to_name(Uid::from_raw(raw));
        assert_eq!(a, b);
    }

    #[test]
    fn gid_cache_memoises() {
        let raw = 999_997u32;
        let _ = gid_to_name(Gid::from_raw(raw));
        let cache = gid_cache().lock().unwrap();
        assert!(cache.contains_key(&raw));
    }
}
