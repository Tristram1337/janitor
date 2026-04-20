//! `diff`: show what would change if a backup were restored (vs current state).
//! `export`: dump a backup in human-readable or JSON form.

use std::fs;
use std::os::unix::fs::MetadataExt;

use serde::Serialize;

use crate::backup::load_backup;
use crate::errors::Result;

#[derive(Debug, Serialize)]
pub struct DiffEntry {
    pub path: String,
    pub current_mode: Option<String>,
    pub snapshot_mode: String,
    pub current_uid: Option<u32>,
    pub snapshot_uid: u32,
    pub current_gid: Option<u32>,
    pub snapshot_gid: u32,
    pub has_acl_change: bool,
}

pub fn cmd_diff(backup_id: &str, as_json: bool) -> Result<()> {
    let data = load_backup(backup_id)?;
    let mut diffs: Vec<DiffEntry> = Vec::new();

    for e in &data.entries {
        let cur = fs::symlink_metadata(&e.path).ok();
        let (cur_mode, cur_uid, cur_gid) = match &cur {
            Some(md) => (Some(md.mode() & 0o7777), Some(md.uid()), Some(md.gid())),
            None => (None, None, None),
        };
        let mode_differs = cur_mode.map(|m| m != e.perm).unwrap_or(true);
        let uid_differs = cur_uid.map(|u| u != e.uid).unwrap_or(true);
        let gid_differs = cur_gid.map(|g| g != e.gid).unwrap_or(true);
        let acl_differs = e.acl.is_some() || e.default_acl.is_some();
        if !mode_differs && !uid_differs && !gid_differs && !acl_differs {
            continue;
        }
        diffs.push(DiffEntry {
            path: e.path.display().to_string(),
            current_mode: cur_mode.map(|m| format!("{m:04o}")),
            snapshot_mode: format!("{:04o}", e.perm),
            current_uid: cur_uid,
            snapshot_uid: e.uid,
            current_gid: cur_gid,
            snapshot_gid: e.gid,
            has_acl_change: acl_differs,
        });
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&diffs).unwrap_or_else(|_| "[]".into())
        );
    } else if diffs.is_empty() {
        println!(
            "(no differences between backup {} and current state)",
            backup_id
        );
    } else {
        println!("diff for backup: {}", backup_id);
        println!(
            "{:>4}  {:>4}  {:>8}→{:>8}  {:>5}→{:>5}  {:>5}→{:>5}  {}",
            "acl", "?", "mode", "mode", "uid", "uid", "gid", "gid", "path"
        );
        for d in &diffs {
            println!(
                "{:>4}  {:>4}  {:>8}→{:>8}  {:>5}→{:>5}  {:>5}→{:>5}  {}",
                if d.has_acl_change { "YES" } else { "-" },
                "",
                d.current_mode.as_deref().unwrap_or("---"),
                d.snapshot_mode,
                d.current_uid
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "-".into()),
                d.snapshot_uid,
                d.current_gid
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "-".into()),
                d.snapshot_gid,
                d.path
            );
        }
        eprintln!("({} entr(ies) differ)", diffs.len());
    }
    Ok(())
}

pub fn cmd_export(backup_id: &str, as_json: bool) -> Result<()> {
    let data = load_backup(backup_id)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("backup: {}", data.id);
        println!("timestamp: {}", data.timestamp);
        println!("operation: {}", data.operation.op_type);
        if let Some(u) = &data.operation.user {
            println!("user: {u}");
        }
        if let Some(g) = &data.operation.group {
            println!("group: {g}");
        }
        if let Some(t) = &data.operation.target {
            println!("target: {t}");
        }
        if let Some(a) = &data.operation.access {
            println!("access: {a}");
        }
        println!("entries: {}", data.entries.len());
        println!();
        println!(
            "{:>6}  {:>5}  {:>5}  {:>3}  {:>3}  {}",
            "mode", "uid", "gid", "sym", "acl", "path"
        );
        for e in &data.entries {
            println!(
                "{:06o}  {:>5}  {:>5}  {:>3}  {:>3}  {}",
                e.perm,
                e.uid,
                e.gid,
                if e.is_symlink { "yes" } else { "-" },
                if e.acl.is_some() { "yes" } else { "-" },
                e.path.display()
            );
        }
    }
    Ok(())
}
