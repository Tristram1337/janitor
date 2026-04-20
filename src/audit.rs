//! `audit`: scan a directory tree and list files matching criteria.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::unistd::{Gid, Uid};
use serde::Serialize;

use crate::acl::has_extended_acl;
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::matcher::ExcludeSet;
use crate::users::{gid_to_name, uid_to_name};

#[derive(Debug, Serialize)]
pub struct AuditHit {
    pub path: String,
    pub mode: String,
    pub uid: u32,
    pub user: String,
    pub gid: u32,
    pub group: String,
    pub has_acl: bool,
    pub size: u64,
}

pub struct AuditFilter<'a> {
    pub world_writable: bool,
    pub world_readable: bool,
    pub world_executable: bool,
    pub setuid: bool,
    pub setgid: bool,
    pub sticky: bool,
    pub owner_uid: Option<u32>,
    pub owner_user: Option<&'a str>,
    pub group_gid: Option<u32>,
    pub group_name: Option<&'a str>,
    pub mode_equals: Option<u32>,
    pub has_acl: bool,
    pub no_owner: bool,
    pub no_group: bool,
}

/// Low-level scan: returns matching hits. Shared by `audit`, `find`, and
/// `audit --fix`.
pub fn scan(path: &Path, filter: &AuditFilter, exclude: &ExcludeSet) -> Vec<AuditHit> {
    let mut hits: Vec<AuditHit> = Vec::new();
    for entry in walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if exclude.is_excluded(p) {
            continue;
        }
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mode = md.mode() & 0o7777;
        let uid = md.uid();
        let gid = md.gid();

        if filter.world_writable && (mode & 0o002) == 0 {
            continue;
        }
        if filter.world_readable && (mode & 0o004) == 0 {
            continue;
        }
        if filter.world_executable && (mode & 0o001) == 0 {
            continue;
        }
        if filter.setuid && (mode & 0o4000) == 0 {
            continue;
        }
        if filter.setgid && (mode & 0o2000) == 0 {
            continue;
        }
        if filter.sticky && (mode & 0o1000) == 0 {
            continue;
        }
        if let Some(u) = filter.owner_uid {
            if uid != u {
                continue;
            }
        }
        if let Some(g) = filter.group_gid {
            if gid != g {
                continue;
            }
        }
        if let Some(owner) = filter.owner_user {
            if uid_to_name(Uid::from_raw(uid)) != owner {
                continue;
            }
        }
        if let Some(group) = filter.group_name {
            if gid_to_name(Gid::from_raw(gid)) != group {
                continue;
            }
        }
        if let Some(m) = filter.mode_equals {
            if mode != m {
                continue;
            }
        }
        if filter.no_owner
            && nix::unistd::User::from_uid(Uid::from_raw(uid))
                .ok()
                .flatten()
                .is_some()
        {
            continue;
        }
        if filter.no_group
            && nix::unistd::Group::from_gid(Gid::from_raw(gid))
                .ok()
                .flatten()
                .is_some()
        {
            continue;
        }
        let acl = has_extended_acl(p);
        if filter.has_acl && !acl {
            continue;
        }

        hits.push(AuditHit {
            path: p.display().to_string(),
            mode: format!("{:04o}", mode),
            uid,
            user: uid_to_name(Uid::from_raw(uid)),
            gid,
            group: gid_to_name(Gid::from_raw(gid)),
            has_acl: acl,
            size: md.len(),
        });
    }
    hits
}

pub fn cmd_audit(
    path: &str,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    as_json: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let hits = scan(&root, filter, exclude);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&hits).unwrap_or_else(|_| "[]".into())
        );
    } else {
        if hits.is_empty() {
            println!("(no matches)");
        } else {
            println!(
                "{:>6}  {:>8}  {:>8}  {:>4}  {}",
                "mode", "user", "group", "acl", "path"
            );
            for h in &hits {
                println!(
                    "{:>6}  {:>8}  {:>8}  {:>4}  {}",
                    h.mode,
                    h.user,
                    h.group,
                    if h.has_acl { "yes" } else { "-" },
                    h.path
                );
            }
            eprintln!("({} match(es))", hits.len());
        }
    }
    Ok(())
}

/// `audit --fix ACTION`: find + mutate in one transaction.
pub fn cmd_audit_fix(
    path: &str,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    action: &str,
    dry_run: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let hits = scan(&root, filter, exclude);
    if hits.is_empty() {
        println!("(no matches; nothing to fix)");
        return Ok(());
    }
    let paths: Vec<String> = hits.iter().map(|h| h.path.clone()).collect();
    println!("audit --fix: {} path(s) → {action}", paths.len());
    let empty = ExcludeSet::default();
    let parts: Vec<&str> = action.splitn(2, ' ').collect();
    match parts.as_slice() {
        ["chmod", arg] => {
            crate::chperm::cmd_chmod(arg.trim(), &paths, false, false, None, &empty, dry_run)
        }
        ["chown", arg] => {
            crate::chperm::cmd_chown(arg.trim(), &paths, false, false, None, &empty, dry_run)
        }
        ["preset", name] => {
            crate::presets::cmd_apply_preset(name.trim(), &paths, false, &empty, dry_run)
        }
        ["strip-world-write"] => {
            crate::chperm::cmd_chmod("o-w", &paths, false, false, None, &empty, dry_run)
        }
        ["strip-setuid"] => {
            crate::chperm::cmd_chmod("u-s", &paths, false, false, None, &empty, dry_run)
        }
        ["strip-setgid"] => {
            crate::chperm::cmd_chmod("g-s", &paths, false, false, None, &empty, dry_run)
        }
        ["strip-sticky"] => {
            crate::chperm::cmd_chmod("-t", &paths, false, false, None, &empty, dry_run)
        }
        _ => Err(crate::errors::PmError::Other(format!(
            "unsupported --fix action: {action:?}  (try `chmod MODE`, `chown SPEC`, \
`preset NAME`, `strip-world-write`, `strip-setuid`, `strip-setgid`, `strip-sticky`)"
        ))),
    }
}

/// `find-orphans`: files with non-existent owner/group.
pub fn cmd_find_orphans(path: &str, as_json: bool) -> Result<()> {
    let filter = AuditFilter {
        world_writable: false,
        world_readable: false,
        world_executable: false,
        setuid: false,
        setgid: false,
        sticky: false,
        owner_uid: None,
        owner_user: None,
        group_gid: None,
        group_name: None,
        mode_equals: None,
        has_acl: false,
        no_owner: true,
        no_group: false,
    };
    // To report orphaned owner OR orphaned group we'd need two passes;
    // instead use a combined walker:
    let root = resolve_path(path)?;
    let mut hits: Vec<AuditHit> = Vec::new();
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let uid = md.uid();
        let gid = md.gid();
        let has_u = nix::unistd::User::from_uid(Uid::from_raw(uid))
            .ok()
            .flatten()
            .is_some();
        let has_g = nix::unistd::Group::from_gid(Gid::from_raw(gid))
            .ok()
            .flatten()
            .is_some();
        if has_u && has_g {
            continue;
        }
        hits.push(AuditHit {
            path: p.display().to_string(),
            mode: format!("{:04o}", md.mode() & 0o7777),
            uid,
            user: uid_to_name(Uid::from_raw(uid)),
            gid,
            group: gid_to_name(Gid::from_raw(gid)),
            has_acl: has_extended_acl(p),
            size: md.len(),
        });
    }
    let _ = &filter; // silence unused

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&hits).unwrap_or_else(|_| "[]".into())
        );
    } else if hits.is_empty() {
        println!("(no orphaned files under {})", root.display());
    } else {
        println!("{:>6}  {:>8}  {:>8}  {}", "mode", "user", "group", "path");
        for h in &hits {
            println!("{:>6}  {:>8}  {:>8}  {}", h.mode, h.user, h.group, h.path);
        }
        eprintln!("({} orphaned)", hits.len());
    }
    Ok(())
}

// keep Path import alive
#[allow(dead_code)]
fn _keep() {
    let _ = Path::new("/");
}
