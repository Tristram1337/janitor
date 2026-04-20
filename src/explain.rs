//! `explain PATH`: show why a path has its current effective access for a user.

use crate::errors::Result;
use crate::helpers::resolve_path;
use nix::unistd::{Gid, Uid};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn mode_str(mode: u32) -> String {
    let t = mode & 0o7000;
    let u = (mode >> 6) & 0o7;
    let g = (mode >> 3) & 0o7;
    let o = mode & 0o7;
    format!(
        "{:04o} ({}{}{}{}{}{}{}{}{})",
        mode & 0o7777,
        if u & 4 != 0 { 'r' } else { '-' },
        if u & 2 != 0 { 'w' } else { '-' },
        if u & 1 != 0 { 'x' } else { '-' },
        if g & 4 != 0 { 'r' } else { '-' },
        if g & 2 != 0 { 'w' } else { '-' },
        if g & 1 != 0 { 'x' } else { '-' },
        if o & 4 != 0 { 'r' } else { '-' },
        if o & 2 != 0 { 'w' } else { '-' },
        if o & 1 != 0 { 'x' } else { '-' },
    )
    .replace(
        "0000 ",
        match t {
            0o4000 => "suid ",
            0o2000 => "sgid ",
            0o1000 => "stky ",
            _ => "0000 ",
        },
    )
}

fn user_info(name: Option<&str>) -> Result<(Uid, Vec<Gid>, String)> {
    if let Some(n) = name {
        if let Some(u) = nix::unistd::User::from_name(n)
            .map_err(|e| crate::errors::PmError::Other(e.to_string()))?
        {
            let mut groups = vec![u.gid];
            if let Ok(gs) = nix::unistd::getgrouplist(&std::ffi::CString::new(n).unwrap(), u.gid) {
                for g in gs {
                    if !groups.contains(&g) {
                        groups.push(g);
                    }
                }
            }
            return Ok((u.uid, groups, n.to_string()));
        }
        return Err(crate::errors::PmError::Other(format!("unknown user: {n}")));
    }
    // Current process UID.
    let uid = nix::unistd::getuid();
    let mut groups: Vec<Gid> =
        nix::unistd::getgroups().map_err(|e| crate::errors::PmError::Other(e.to_string()))?;
    let gid = nix::unistd::getgid();
    if !groups.contains(&gid) {
        groups.insert(0, gid);
    }
    let name = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| format!("uid={}", uid.as_raw()));
    Ok((uid, groups, name))
}

fn check_access(path: &Path, uid: Uid, groups: &[Gid]) -> (bool, bool, bool, String) {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return (false, false, false, format!("stat failed: {e}")),
    };
    let mode = md.permissions().mode() & 0o7777;
    let owner = md.uid();
    let grp = md.gid();
    let (r_bits, w_bits, x_bits, reason) = if uid.as_raw() == 0 {
        (true, true, (mode & 0o111) != 0, "root (superuser)".into())
    } else if uid.as_raw() == owner {
        (
            mode & 0o400 != 0,
            mode & 0o200 != 0,
            mode & 0o100 != 0,
            "owner".into(),
        )
    } else if groups.iter().any(|g| g.as_raw() == grp) {
        (
            mode & 0o040 != 0,
            mode & 0o020 != 0,
            mode & 0o010 != 0,
            "group member".into(),
        )
    } else {
        (
            mode & 0o004 != 0,
            mode & 0o002 != 0,
            mode & 0o001 != 0,
            "other".into(),
        )
    };
    (r_bits, w_bits, x_bits, reason)
}

pub fn cmd_explain(path: &str, for_user: Option<&str>) -> Result<()> {
    let target = resolve_path(path)?;
    let (uid, groups, uname) = user_info(for_user)?;
    println!("explain: {} (as user {uname})", target.display());
    println!();

    // Walk ancestors top-down, checking traversal (x on each directory).
    let mut chain: Vec<PathBuf> = Vec::new();
    let mut cur = target.as_path();
    chain.push(cur.to_path_buf());
    while let Some(parent) = cur.parent() {
        chain.push(parent.to_path_buf());
        if parent == Path::new("/") {
            break;
        }
        cur = parent;
    }
    chain.reverse();

    let mut traversable = true;
    for p in &chain {
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) => {
                println!("  {} (unreadable: {e})", p.display());
                traversable = false;
                continue;
            }
        };
        let mode = md.permissions().mode() & 0o7777;
        let acl = crate::acl::has_extended_acl(p);
        let (_r, _w, x, reason) = check_access(p, uid, &groups);
        let is_last = p == &target;
        let marker = if is_last { "→" } else { " " };
        println!(
            "  {marker} {}  {}  owner={} group={} [{}]{}",
            p.display(),
            mode_str(mode),
            crate::users::uid_to_name(Uid::from_raw(md.uid())),
            crate::users::gid_to_name(Gid::from_raw(md.gid())),
            reason,
            if acl { " +acl" } else { "" }
        );
        if !is_last && p.is_dir() && !x {
            traversable = false;
            println!("      (no traverse bit; blocks access to children)");
        }
    }

    println!();
    let (r, w, x, reason) = check_access(&target, uid, &groups);
    let r = r && traversable;
    let w = w && traversable;
    let x = x && traversable;
    println!(
        "verdict for {uname}: read={} write={} exec={}  ({})",
        if r { "YES" } else { "no" },
        if w { "YES" } else { "no" },
        if x { "YES" } else { "no" },
        reason
    );
    if !traversable {
        println!("  NOTE: an ancestor directory lacks the x (traverse) bit.");
    }
    Ok(())
}
