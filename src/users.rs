//! Username / UID / GID lookups and group-membership queries.

use nix::unistd::{Gid, Group, Uid, User};

use crate::errors::{PmError, Result};

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
pub fn uid_to_name(uid: Uid) -> String {
    User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

/// Resolve a gid to a group name, fallback to numeric string.
pub fn gid_to_name(gid: Gid) -> String {
    Group::from_gid(gid)
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| gid.to_string())
}
