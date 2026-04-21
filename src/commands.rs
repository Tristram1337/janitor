//! `grant` / `revoke` / `preset` and other high-level mutation entry points.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::backup::{load_backup, save_backup};
use crate::errors::{PmError, Result};
use crate::groups::{add_user_to_group, ensure_group, remove_user_from_group};
use crate::helpers::{
    default_group_name, parse_access, path_chain, resolve_path, validate_group_name,
};
use crate::locking::with_lock;
use crate::perms::{apply_group_bits, apply_restore};
use crate::render::{self, glyphs, paint, summary_line, DiagLevel, Style};
use crate::snapshot::snapshot_with_acl;
use crate::types::{AccessBits, Operation};
use crate::users::{group_exists, lookup_user, user_in_group};

pub fn cmd_grant(
    user: Option<&str>,
    group: Option<&str>,
    path: &str,
    access: &str,
    max_level: Option<usize>,
    recursive: bool,
    force_all_parents: bool,
    capture_acl: bool,
    dry_run: bool,
) -> Result<()> {
    if user.is_none() && group.is_none() {
        return Err(PmError::NoUserOrGroup);
    }
    if let Some(u) = user {
        lookup_user(u)?; // fail fast
    }

    let target = resolve_path(path)?;
    crate::locks::ensure_not_locked(&target)?;
    let access_bits = parse_access(access)?;

    // Decide managed group.
    let group_name = match group {
        Some(g) => {
            validate_group_name(g)?;
            g.to_string()
        }
        None => default_group_name(&target),
    };

    let stdout_tty = is_terminal::is_terminal(std::io::stdout());
    let g = glyphs();

    // ── Title line (TTY only) ────────────────────────────────────────
    if stdout_tty {
        let u_disp = user.unwrap_or("-");
        let marker = if dry_run { "  [DRY RUN]" } else { "" };
        println!(
            "{} janitor grant {} {} {}{}",
            paint(Style::Separator, g.header_marker),
            paint(Style::User, u_disp),
            paint(Style::Primary, access),
            paint(Style::Primary, &target.display().to_string()),
            paint(Style::WarnMajor, marker)
        );
        println!();
    }

    // ── World-readable warning (top of block) ────────────────────────
    if let Ok(md) = std::fs::symlink_metadata(&target) {
        let other_bits = md.mode() & 0o007;
        if other_bits & 0o004 != 0 {
            render::eprint_diag(
                DiagLevel::Warning,
                &format!(
                    "{} is world-readable (o={:03o}); managed-group isolation won't help \
                     until 'other' read bit is cleared.",
                    target.display(),
                    other_bits
                ),
                Some(&format!(
                    "fix first: janitor chmod o-r {}",
                    target.display()
                )),
                &[],
            );
        }
    }

    // ── Narrate: group ensure + user add (dry-run predicts; apply acts) ─
    let group_existed = group_exists(&group_name);
    let user_in = user
        .map(|u| user_in_group(u, &group_name))
        .unwrap_or(true);
    narrate_action(
        stdout_tty,
        dry_run,
        group_existed,
        "ensure group",
        &paint(Style::Group, &group_name),
    );
    if !dry_run {
        ensure_group(&group_name, false)?;
    }
    if let Some(u) = user {
        narrate_action(
            stdout_tty,
            dry_run,
            user_in,
            "add user  ",
            &format!(
                "{} {} {}",
                paint(Style::User, u),
                paint(Style::Separator, "→"),
                paint(Style::Group, &group_name)
            ),
        );
        if !dry_run {
            add_user_to_group(u, &group_name, false)?;
        }
    }

    // Build list of paths to touch.
    let chain = path_chain(&target, Path::new("/"));
    let parents = if let Some(n) = max_level {
        let all_parents = &chain[..chain.len().saturating_sub(1)];
        let start = all_parents.len().saturating_sub(n);
        all_parents[start..].to_vec()
    } else {
        chain[..chain.len().saturating_sub(1)].to_vec()
    };

    let filtered_parents: Vec<PathBuf> = parents
        .iter()
        .filter(|p| {
            if force_all_parents {
                return true;
            }
            match std::fs::symlink_metadata(p) {
                Ok(md) => (md.mode() & 0o001) == 0,
                Err(_) => false,
            }
        })
        .cloned()
        .collect();

    // Narrate skipped world-traversable parents.
    for p in &parents {
        if !filtered_parents.contains(p) {
            if stdout_tty {
                println!(
                    "  {} {}  {}  {}",
                    paint(Style::Separator, "─"),
                    paint(Style::Label, "skipped       "),
                    paint(Style::Primary, &p.display().to_string()),
                    paint(Style::Label, "(already world-traversable)")
                );
            }
        }
    }

    let mut touched: Vec<PathBuf> = filtered_parents.clone();
    touched.push(chain.last().unwrap().clone());

    with_lock(|| {
        // Save backup early.
        let mut backup_id: Option<String> = None;
        if !dry_run {
            let snap = snapshot_with_acl(&touched, capture_acl);
            let op = Operation {
                op_type: "grant".into(),
                user: user.map(String::from),
                group: Some(group_name.clone()),
                explicit_group: group.map(String::from),
                target: Some(target.display().to_string()),
                access: Some(access.to_string()),
                max_level,
                recursive: Some(recursive),
                parent_op: None,
            };
            backup_id = Some(save_backup(snap, op)?);
        }

        // Parents: exactly `x` (traverse), replace existing group triad.
        let traverse_bits = AccessBits(0o1);
        for p in &filtered_parents {
            let before_mode = std::fs::symlink_metadata(p).map(|m| m.mode() & 0o7777).ok();
            apply_group_bits(p, &group_name, traverse_bits, dry_run, true)?;
            let after_mode = std::fs::symlink_metadata(p).map(|m| m.mode() & 0o7777).ok();
            let verb = if dry_run { "would g+rx   " } else { "chmod g+rx   " };
            if stdout_tty {
                let was = match before_mode {
                    Some(m) => format!("  (was {:04o})", m),
                    None => String::new(),
                };
                let now = match (after_mode, dry_run) {
                    (_, true) => String::new(),
                    (Some(m), false) => format!(" → {:04o}", m),
                    _ => String::new(),
                };
                println!(
                    "  {} {}  {}{}{}  {}",
                    paint(Style::Ok, g.check),
                    paint(Style::Label, verb),
                    paint(Style::Primary, &p.display().to_string()),
                    paint(Style::Label, &was),
                    paint(Style::Label, &now),
                    paint(Style::Label, "(parent traverse)")
                );
            }
        }

        // Target.
        let t_before = std::fs::symlink_metadata(&target)
            .map(|m| m.mode() & 0o7777)
            .ok();
        apply_group_bits(
            touched.last().unwrap(),
            &group_name,
            access_bits,
            dry_run,
            false,
        )?;
        let t_after = std::fs::symlink_metadata(&target)
            .map(|m| m.mode() & 0o7777)
            .ok();
        if stdout_tty {
            let verb = if dry_run {
                format!("would chgrp  ")
            } else {
                format!("chgrp        ")
            };
            println!(
                "  {} {}  {} → {}",
                paint(Style::Ok, g.check),
                paint(Style::Label, &verb),
                paint(Style::Primary, &target.display().to_string()),
                paint(Style::Group, &group_name)
            );
            let verb2 = if dry_run { "would chmod  " } else { "chmod        " };
            let was = t_before
                .map(|m| format!("  (was {:04o})", m))
                .unwrap_or_default();
            let now = match (t_after, dry_run) {
                (_, true) => String::new(),
                (Some(m), false) => format!(" → {:04o}", m),
                _ => String::new(),
            };
            println!(
                "  {} {}  {}{}{}  {}",
                paint(Style::Ok, g.check),
                paint(Style::Label, verb2),
                paint(Style::Primary, &target.display().to_string()),
                paint(Style::Label, &was),
                paint(Style::Label, &now),
                paint(Style::Label, &format!("(group +{})", access))
            );
        }

        // Recursive branch (unchanged logic, lightweight narration).
        if recursive && target.is_dir() {
            let extra = collect_recursive(&target);
            if !dry_run && !extra.is_empty() {
                let snap2 = snapshot_with_acl(&extra, capture_acl);
                if !snap2.is_empty() {
                    let bid2 = save_backup(
                        snap2,
                        Operation {
                            op_type: "grant-recursive-extra".into(),
                            user: user.map(String::from),
                            group: Some(group_name.clone()),
                            explicit_group: group.map(String::from),
                            target: Some(target.display().to_string()),
                            access: Some(access.to_string()),
                            max_level: None,
                            recursive: Some(true),
                            parent_op: None,
                        },
                    )?;
                    if stdout_tty {
                        println!(
                            "  {} {}  {} {} {}",
                            paint(Style::Ok, g.check),
                            paint(Style::Label, "recursive    "),
                            paint(Style::Primary, &extra.len().to_string()),
                            paint(Style::Label, "entries (backup"),
                            paint(Style::Primary, &format!("{bid2})"))
                        );
                    }
                }
            }
            extra
                .par_iter()
                .try_for_each(|p| apply_group_bits(p, &group_name, access_bits, dry_run, false))?;
        }

        // ── Footer: backup/undo/verify block ─────────────────────────
        println!();
        if let Some(bid) = &backup_id {
            println!(
                "{}  {}",
                paint(Style::Label, "backup:"),
                paint(Style::Primary, bid)
            );
            if stdout_tty {
                println!(
                    "{}    {}",
                    paint(Style::Label, "undo:"),
                    paint(Style::Primary, "janitor undo")
                );
                if let Some(u) = user {
                    println!(
                        "{}  {}",
                        paint(Style::Label, "verify:"),
                        paint(
                            Style::Primary,
                            &format!("sudo -u {} cat {}", u, target.display())
                        )
                    );
                }
            }
        } else {
            // dry-run footer
            let segs: Vec<(&str, &str)> = vec![("dry run", "— nothing changed")];
            let mut s = summary_line(&segs);
            s.push_str("  ");
            s.push_str(&paint(Style::Label, "(re-run without --dry-run to apply)"));
            println!("{s}");
        }
        Ok(())
    })
}

fn narrate_action(tty: bool, dry_run: bool, already_ok: bool, verb: &str, subject: &str) {
    if !tty {
        return;
    }
    let g = glyphs();
    if already_ok {
        println!(
            "  {} {}  {}  {}",
            paint(Style::Separator, "─"),
            paint(Style::Label, verb),
            subject,
            paint(Style::Label, "(already present)")
        );
    } else if dry_run {
        println!(
            "  {} {}  {}",
            paint(Style::Label, "would"),
            paint(Style::Label, verb),
            subject
        );
    } else {
        println!(
            "  {} {}  {}",
            paint(Style::Ok, g.check),
            paint(Style::Label, verb),
            subject
        );
    }
}

/// Collect all entries under a directory (excluding root itself).
fn collect_recursive(target: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(target)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .collect()
}

pub fn cmd_revoke(user: &str, path: &str, group: Option<&str>, dry_run: bool) -> Result<()> {
    let target = resolve_path(path)?;
    let group_name = match group {
        Some(g) => g.to_string(),
        None => default_group_name(&target),
    };
    let changed = remove_user_from_group(user, &group_name, dry_run)?;
    if changed && !dry_run {
        println!("removed {user} from {group_name}");
        println!("note: file mode/ownership unchanged; use `restore <id>` for full revert.");
    }
    Ok(())
}

pub fn cmd_backup(path: &str, recursive: bool, capture_acl: bool) -> Result<()> {
    let target = resolve_path(path)?;
    let mut paths = vec![target.clone()];
    if recursive && target.is_dir() {
        paths.extend(collect_recursive(&target));
    }
    with_lock(|| {
        let snap = snapshot_with_acl(&paths, capture_acl);
        let count = snap.len();
        let bid = save_backup(
            snap,
            Operation {
                op_type: "manual-backup".into(),
                user: None,
                group: None,
                explicit_group: None,
                target: Some(target.display().to_string()),
                access: None,
                max_level: None,
                recursive: Some(recursive),
                parent_op: None,
            },
        )?;
        println!("backup: {bid}  ({count} entries)");
        Ok(())
    })
}

pub fn cmd_restore(backup_id: &str, dry_run: bool) -> Result<()> {
    let data = load_backup(backup_id)?;
    println!(
        "restoring {backup_id} (op: {}, {} entries)",
        data.operation.op_type,
        data.entries.len()
    );
    let errors = apply_restore(&data.entries, dry_run);
    if errors > 0 {
        Err(PmError::Other(format!("{errors} error(s) during restore")))
    } else {
        Ok(())
    }
}

/// Undo the most recent backup (newest by file mtime).
pub fn cmd_undo(dry_run: bool) -> Result<()> {
    let files = crate::backup::list_backup_files()?;
    let latest = files
        .iter()
        .max_by_key(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH)
        })
        .ok_or_else(|| PmError::Other("no backups to undo".into()))?;
    let bid = latest
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| PmError::Other("invalid backup filename".into()))?
        .to_string();
    println!("undo: restoring latest backup {bid}");
    cmd_restore(&bid, dry_run)
}

/// Parse `1h`, `30m`, `2d`, `1w`, `45s` into a `chrono::Duration`.
fn parse_since(s: &str) -> Result<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(PmError::Other("empty --since duration".into()));
    }
    let (num, unit) = s.split_at(
        s.char_indices()
            .find(|(_, c)| !c.is_ascii_digit())
            .map(|(i, _)| i)
            .unwrap_or(s.len()),
    );
    let n: i64 = num
        .parse()
        .map_err(|_| PmError::Other(format!("invalid --since: {s}")))?;
    Ok(match unit {
        "s" | "" => chrono::Duration::seconds(n),
        "m" => chrono::Duration::minutes(n),
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        "w" => chrono::Duration::weeks(n),
        other => {
            return Err(PmError::Other(format!(
                "invalid --since unit `{other}` (use s/m/h/d/w)"
            )))
        }
    })
}

/// Print backup history for a path substring (newest first).
pub fn cmd_history(path: &str, since: Option<&str>, as_json: bool) -> Result<()> {
    let cutoff = since
        .map(parse_since)
        .transpose()?
        .map(|d| chrono::Utc::now() - d);
    let files = crate::backup::list_backup_files()?;
    let mut rows: Vec<crate::types::Backup> = Vec::new();
    for f in &files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        let data: std::result::Result<crate::types::Backup, String> = match ext {
            "mpk" => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    rmp_serde::from_read(std::io::BufReader::new(fh)).map_err(|e| e.to_string())
                }),
            _ => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    serde_json::from_reader::<_, crate::types::Backup>(std::io::BufReader::new(fh))
                        .map_err(|e| e.to_string())
                }),
        };
        if let Ok(b) = data {
            let target_match = b
                .operation
                .target
                .as_deref()
                .map(|t| t.contains(path))
                .unwrap_or(false);
            if !target_match {
                continue;
            }
            if let Some(cut) = cutoff {
                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&b.timestamp) {
                    if ts.with_timezone(&chrono::Utc) < cut {
                        continue;
                    }
                }
            }
            rows.push(b);
        }
    }
    rows.reverse(); // newest first
    if as_json {
        let out: Vec<serde_json::Value> = rows
            .iter()
            .map(|b| {
                serde_json::json!({
                    "id": b.id,
                    "timestamp": b.timestamp,
                    "type": b.operation.op_type,
                    "user": b.operation.user,
                    "target": b.operation.target,
                    "entries": b.entries.len(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!("(no backups touching {path})");
        return Ok(());
    }
    println!(
        "{:25}  {:19}  {:22}  {:10}  target",
        "id", "timestamp", "type", "user"
    );
    println!("{}", "-".repeat(110));
    for b in &rows {
        println!(
            "{:25}  {:19}  {:22}  {:10}  {}",
            b.id,
            b.timestamp,
            b.operation.op_type,
            b.operation.user.as_deref().unwrap_or("-"),
            b.operation.target.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

pub fn cmd_lock(path: &str, reason: Option<&str>) -> Result<()> {
    let p = resolve_path(path)?;
    crate::locks::add(&p, reason)?;
    println!("locked: {}", p.display());
    Ok(())
}

pub fn cmd_unlock(path: &str) -> Result<()> {
    let p = resolve_path(path)?;
    crate::locks::remove(&p)?;
    println!("unlocked: {}", p.display());
    Ok(())
}

pub fn cmd_locks(as_json: bool) -> Result<()> {
    let locks = crate::locks::load()?;
    if as_json {
        let out: Vec<serde_json::Value> = locks
            .iter()
            .map(|l| serde_json::json!({ "path": l.path, "reason": l.reason }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if locks.is_empty() {
        println!("(no active locks)");
        return Ok(());
    }
    println!("{:60}  reason", "path");
    println!("{}", "-".repeat(90));
    for l in &locks {
        println!("{:60}  {}", l.path.display(), l.reason);
    }
    Ok(())
}

pub fn cmd_list_backups(as_json: bool, path_substr: Option<&str>) -> Result<()> {
    let files = crate::backup::list_backup_files()?;
    // Helper closure: check whether a loaded backup matches the optional target filter.
    let matches_filter = |b: &crate::types::Backup| -> bool {
        match path_substr {
            None => true,
            Some(s) => b
                .operation
                .target
                .as_deref()
                .map(|t| t.contains(s))
                .unwrap_or(false),
        }
    };
    if as_json {
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for f in &files {
            let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
            let data_res: std::result::Result<crate::types::Backup, String> = match ext {
                "mpk" => std::fs::File::open(f)
                    .map_err(|e| e.to_string())
                    .and_then(|fh| {
                        rmp_serde::from_read(std::io::BufReader::new(fh)).map_err(|e| e.to_string())
                    }),
                _ => std::fs::File::open(f)
                    .map_err(|e| e.to_string())
                    .and_then(|fh| {
                        serde_json::from_reader::<_, crate::types::Backup>(std::io::BufReader::new(
                            fh,
                        ))
                        .map_err(|e| e.to_string())
                    }),
            };
            if let Ok(data) = data_res {
                if !matches_filter(&data) {
                    continue;
                }
                rows.push(serde_json::json!({
                    "id": data.id,
                    "timestamp": data.timestamp,
                    "type": data.operation.op_type,
                    "user": data.operation.user,
                    "group": data.operation.group,
                    "target": data.operation.target,
                    "entries": data.entries.len(),
                }));
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if files.is_empty() {
        println!("(no backups in {})", crate::config::backup_root().display());
        return Ok(());
    }
    println!("{:25}  {:22}  {:10}  target", "id", "type", "user");
    println!("{}", "-".repeat(100));
    for f in &files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        let read_result: std::result::Result<crate::types::Backup, String> = match ext {
            "mpk" => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    rmp_serde::from_read(std::io::BufReader::new(fh)).map_err(|e| e.to_string())
                }),
            _ => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    serde_json::from_reader::<_, crate::types::Backup>(std::io::BufReader::new(fh))
                        .map_err(|e| e.to_string())
                }),
        };
        match read_result {
            Ok(data) => {
                if !matches_filter(&data) {
                    continue;
                }
                println!(
                    "{:25}  {:22}  {:10}  {}",
                    data.id,
                    data.operation.op_type,
                    data.operation.user.as_deref().unwrap_or("-"),
                    data.operation.target.as_deref().unwrap_or("-"),
                );
            }
            Err(e) => {
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
                println!("{stem:25}  <corrupt: {e}>");
            }
        }
    }
    Ok(())
}
