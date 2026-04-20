//! `who-can`: reverse query, list users who can {read,write,exec} a path
//! based on owner/group/other bits plus group memberships.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::unistd::{Gid, Uid};
use serde::Serialize;

use crate::errors::Result;
use crate::helpers::{path_chain, resolve_path};
use crate::users::{gid_to_name, uid_to_name, user_gids};

#[derive(Debug, Serialize)]
pub struct WhoCanReport {
    pub path: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub exec: Vec<String>,
    pub blocked_by: Option<String>,
}

pub fn cmd_who_can(path: &str, as_json: bool) -> Result<()> {
    let target = resolve_path(path)?;
    // Traverse-ability: every parent must be at least o+x or the querying
    // subject must be covered by the group/owner bits.
    let chain = path_chain(&target, Path::new("/"));
    let md = fs::symlink_metadata(&target)?;
    let mode = md.mode() & 0o7777;
    let uid = md.uid();
    let gid = md.gid();

    // Collect all known users from /etc/passwd.
    let users = read_passwd_users();

    let mut r_users = Vec::new();
    let mut w_users = Vec::new();
    let mut x_users = Vec::new();

    for u in &users {
        if user_has_bit(u, &chain, &target, 0o4, uid, gid, mode) {
            r_users.push(u.name.clone());
        }
        if user_has_bit(u, &chain, &target, 0o2, uid, gid, mode) {
            w_users.push(u.name.clone());
        }
        if user_has_bit(u, &chain, &target, 0o1, uid, gid, mode) {
            x_users.push(u.name.clone());
        }
    }

    // Find first parent that blocks traversal for a generic non-priv user.
    let blocked_by = chain
        .iter()
        .take(chain.len().saturating_sub(1))
        .find(|p| {
            fs::symlink_metadata(p)
                .map(|m| (m.mode() & 0o001) == 0)
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string());

    let report = WhoCanReport {
        path: target.display().to_string(),
        read: r_users,
        write: w_users,
        exec: x_users,
        blocked_by,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("access report for: {}", report.path);
        println!("  owner: {} ({})", uid_to_name(Uid::from_raw(uid)), uid);
        println!("  group: {} ({})", gid_to_name(Gid::from_raw(gid)), gid);
        println!("  mode:  {:04o}", mode);
        if let Some(b) = &report.blocked_by {
            println!("  NOTE: parent {b} blocks traversal for non-priv users.");
        }
        println!();
        print_users("read", &report.read);
        print_users("write", &report.write);
        print_users("exec", &report.exec);
    }
    Ok(())
}

fn print_users(label: &str, names: &[String]) {
    if names.is_empty() {
        println!("  {label:<6} (none beyond root)");
    } else if names.len() > 20 {
        println!("  {label:<6} {} users", names.len());
    } else {
        println!("  {label:<6} {}", names.join(", "));
    }
}

struct UserRow {
    name: String,
    uid: u32,
}

fn read_passwd_users() -> Vec<UserRow> {
    let mut out = Vec::new();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            if let Ok(uid) = parts[2].parse::<u32>() {
                out.push(UserRow {
                    name: parts[0].to_string(),
                    uid,
                });
            }
        }
    }
    out
}

fn user_has_bit(
    user: &UserRow,
    chain: &[std::path::PathBuf],
    target: &Path,
    bit: u32,
    target_uid: u32,
    target_gid: u32,
    target_mode: u32,
) -> bool {
    if user.uid == 0 {
        return true;
    }
    // Must traverse all parents (o+x OR owner/group with x).
    for p in &chain[..chain.len().saturating_sub(1)] {
        if let Ok(md) = fs::symlink_metadata(p) {
            let m = md.mode() & 0o7777;
            let pu = md.uid();
            let pg = md.gid();
            let ok = if user.uid == pu {
                (m & 0o100) != 0
            } else if user_in_gid(user.uid, pg) {
                (m & 0o010) != 0
            } else {
                (m & 0o001) != 0
            };
            if !ok {
                return false;
            }
        } else {
            return false;
        }
    }
    // Now check the target itself.
    let _ = target;
    if user.uid == target_uid {
        return (target_mode & (bit << 6)) != 0;
    }
    if user_in_gid(user.uid, target_gid) {
        return (target_mode & (bit << 3)) != 0;
    }
    (target_mode & bit) != 0
}

fn user_in_gid(uid: u32, gid: u32) -> bool {
    // Get the user name first.
    let name = uid_to_name(Uid::from_raw(uid));
    let gids = user_gids(&name).unwrap_or_default();
    gids.iter().any(|g| g.as_raw() == gid)
}
