//! `chmod` and `chown` subcommands with automatic snapshot/backup.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::backup::save_backup;
use crate::errors::{PmError, Result};
use crate::helpers::resolve_path;
use crate::locking::with_lock;
use crate::matcher::ExcludeSet;
use crate::render::{paint, summary_line, Style};
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use crate::users::{gid_to_name, lookup_group, lookup_user, uid_to_name};

/// Resolve each input path, enforce `ensure_not_locked`, and expand to a flat
/// list honoring `recursive` + `exclude`. Returns `(resolved_targets, paths)`.
/// Fail-closed: any missing / locked path aborts before any mutation.
pub fn expand_targets(
    paths_in: &[String],
    recursive: bool,
    exclude: &ExcludeSet,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut paths = Vec::new();
    let mut resolved_targets = Vec::new();
    for p in paths_in {
        let t = resolve_path(p)?;
        crate::locks::ensure_not_locked(&t)?;
        resolved_targets.push(t.clone());
        if exclude.is_excluded(&t) {
            continue;
        }
        paths.push(t.clone());
        if recursive && t.is_dir() {
            for entry in walkdir::WalkDir::new(&t)
                .min_depth(1)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let ep = entry.into_path();
                if exclude.is_excluded(&ep) {
                    continue;
                }
                paths.push(ep);
            }
        }
    }
    Ok((resolved_targets, paths))
}

/// Apply a chmod (octal or symbolic, or a fixed `ref_mode`) to each path in
/// `paths`. Does NOT take a snapshot; the caller must record its own backup.
/// Returns (changed, unchanged, failed) counts.
pub fn apply_chmod_to_paths(
    paths: &[PathBuf],
    mode_spec: &str,
    ref_mode: Option<u32>,
    dry_run: bool,
) -> Result<(usize, usize, usize)> {
    let stderr_tty = is_terminal::is_terminal(std::io::stderr());
    let mut changed = 0usize;
    let mut unchanged = 0usize;
    let mut failed = 0usize;
    for p in paths {
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        if md.file_type().is_symlink() {
            continue;
        }
        let current = md.permissions().mode() & 0o7777;
        let new_mode = if let Some(m) = ref_mode {
            m
        } else if mode_spec
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            parse_octal(mode_spec)?
        } else {
            apply_symbolic(current, mode_spec, md.is_dir())?
        };
        if new_mode == current {
            unchanged += 1;
            continue;
        }
        if dry_run {
            if stderr_tty {
                eprintln!(
                    "  [dry-run] {:04o} {} {:04o}  {}",
                    current,
                    paint(Style::Separator, "→"),
                    new_mode,
                    paint(Style::Primary, &p.display().to_string())
                );
            } else {
                eprintln!(
                    "[dry-run] chmod {new_mode:04o} {}  (was {current:04o})",
                    p.display()
                );
            }
            changed += 1;
        } else {
            match fs::set_permissions(p, fs::Permissions::from_mode(new_mode)) {
                Ok(()) => {
                    if stderr_tty {
                        eprintln!(
                            "  {:04o} {} {:04o}  {}",
                            current,
                            paint(Style::Separator, "→"),
                            new_mode,
                            paint(Style::Primary, &p.display().to_string())
                        );
                    }
                    changed += 1;
                }
                Err(e) => {
                    failed += 1;
                    eprintln!(
                        "  {}: {}  {}",
                        paint(Style::Danger, "error"),
                        p.display(),
                        e
                    );
                }
            }
        }
    }
    Ok((changed, unchanged, failed))
}

/// Apply a chown (uid / gid, either optional) to each path. No snapshot.
/// Returns (changed, unchanged, failed).
pub fn apply_chown_to_paths(
    paths: &[PathBuf],
    new_uid: Option<u32>,
    new_gid: Option<u32>,
    dry_run: bool,
) -> Result<(usize, usize, usize)> {
    use nix::unistd::{Gid, Uid};
    let stderr_tty = is_terminal::is_terminal(std::io::stderr());
    let mut changed = 0usize;
    let mut unchanged = 0usize;
    let mut failed = 0usize;
    let u_name = new_uid
        .map(|u| uid_to_name(Uid::from_raw(u)))
        .unwrap_or_else(|| "(keep)".into());
    let g_name = new_gid
        .map(|g| gid_to_name(Gid::from_raw(g)))
        .unwrap_or_else(|| "(keep)".into());
    for p in paths {
        let before = fs::symlink_metadata(p).ok();
        let (bu, bg) = match &before {
            Some(m) => (
                uid_to_name(Uid::from_raw(m.uid())),
                gid_to_name(Gid::from_raw(m.gid())),
            ),
            None => ("?".into(), "?".into()),
        };
        let will_change = match &before {
            Some(m) => {
                let u_diff = new_uid.map(|u| u != m.uid()).unwrap_or(false);
                let g_diff = new_gid.map(|g| g != m.gid()).unwrap_or(false);
                u_diff || g_diff
            }
            None => true,
        };
        if !will_change {
            unchanged += 1;
            continue;
        }
        if dry_run {
            eprintln!(
                "  [dry-run] {}:{} {} {}:{}  {}",
                paint(Style::User, &bu),
                paint(Style::Group, &bg),
                paint(Style::Separator, "→"),
                paint(Style::User, &u_name),
                paint(Style::Group, &g_name),
                paint(Style::Primary, &p.display().to_string())
            );
            changed += 1;
        } else {
            match lchown(p, new_uid, new_gid) {
                Ok(()) => {
                    if stderr_tty {
                        eprintln!(
                            "  {}:{} {} {}:{}  {}",
                            paint(Style::User, &bu),
                            paint(Style::Group, &bg),
                            paint(Style::Separator, "→"),
                            paint(Style::User, &u_name),
                            paint(Style::Group, &g_name),
                            paint(Style::Primary, &p.display().to_string())
                        );
                    }
                    changed += 1;
                }
                Err(e) => {
                    failed += 1;
                    eprintln!(
                        "  {}: {}  {}",
                        paint(Style::Danger, "error"),
                        p.display(),
                        e
                    );
                }
            }
        }
    }
    Ok((changed, unchanged, failed))
}

/// Resolve a chown `SPEC` (or `--reference FILE`) to `(uid, gid)`.
pub fn resolve_chown_target(
    spec: &str,
    reference: Option<&str>,
) -> Result<(Option<u32>, Option<u32>)> {
    if let Some(r) = reference {
        let rp = resolve_path(r)?;
        let md = fs::metadata(&rp).map_err(|e| PmError::InsufficientPrivileges {
            path: rp.clone(),
            reason: e.to_string(),
        })?;
        Ok((Some(md.uid()), Some(md.gid())))
    } else {
        parse_chown_spec(spec)
    }
}

/// lchown via libc: does NOT follow symlinks (unlike std::os::unix::fs::chown).
fn lchown(path: &Path, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let u = uid.unwrap_or(u32::MAX); // -1 = don't change
    let g = gid.unwrap_or(u32::MAX);
    let ret = unsafe { libc::lchown(c_path.as_ptr(), u, g) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Parse an octal mode string like "755" or "0755" or "4755" into u32.
pub fn parse_octal(s: &str) -> Result<u32> {
    let trimmed = s.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    u32::from_str_radix(trimmed, 8)
        .map_err(|_| PmError::Other(format!("invalid octal mode: {s:?}")))
        .and_then(|v| {
            if v > 0o7777 {
                Err(PmError::Other(format!("mode out of range: {s:?}")))
            } else {
                Ok(v)
            }
        })
}

/// Apply symbolic mode like "u+r", "g-w", "o=rx", "a+X", "u+s".
/// Returns the new mode given the current one.
pub fn apply_symbolic(current: u32, spec: &str, is_dir: bool) -> Result<u32> {
    let mut mode = current & 0o7777;
    for part in spec.split(',') {
        mode = apply_one(mode, part.trim(), is_dir)?;
    }
    Ok(mode)
}

fn apply_one(mut mode: u32, spec: &str, is_dir: bool) -> Result<u32> {
    // Split into whos and op+perms.
    let op_pos = spec
        .find(|c: char| ['+', '-', '='].contains(&c))
        .ok_or_else(|| PmError::Other(format!("missing +/-/= in symbolic mode: {spec:?}")))?;
    let (whos, rest) = spec.split_at(op_pos);
    let op = rest.chars().next().unwrap();
    let perms = &rest[1..];

    let mut who_mask: u32 = 0;
    if whos.is_empty() || whos.contains('a') {
        who_mask |= 0o700 | 0o070 | 0o007;
    } else {
        for c in whos.chars() {
            match c {
                'u' => who_mask |= 0o700,
                'g' => who_mask |= 0o070,
                'o' => who_mask |= 0o007,
                _ => return Err(PmError::Other(format!("bad who in {spec:?}: {c}"))),
            }
        }
    }

    let mut perm_bits: u32 = 0;
    let mut setid = 0u32;
    let mut sticky = 0u32;
    for c in perms.chars() {
        match c {
            'r' => perm_bits |= 0o444,
            'w' => perm_bits |= 0o222,
            'x' => perm_bits |= 0o111,
            'X' => {
                // Execute only if is a dir OR any existing exec bit.
                if is_dir || (mode & 0o111) != 0 {
                    perm_bits |= 0o111;
                }
            }
            's' => setid = 0o6000, // applies to who-relevant bits below
            't' => sticky = 0o1000,
            _ => return Err(PmError::Other(format!("bad perm in {spec:?}: {c}"))),
        }
    }

    let add_bits = perm_bits & who_mask;
    // Special: 's' with u→suid(4000), s with g→sgid(2000)
    let mut special_add: u32 = 0;
    if setid != 0 {
        if whos.is_empty() || whos.contains('u') || whos.contains('a') {
            special_add |= 0o4000;
        }
        if whos.contains('g') || whos.is_empty() || whos.contains('a') {
            special_add |= 0o2000;
        }
    }
    if sticky != 0 {
        special_add |= 0o1000;
    }

    match op {
        '+' => {
            mode |= add_bits | special_add;
        }
        '-' => {
            mode &= !(add_bits | special_add);
        }
        '=' => {
            // Clear who_mask first, then set.
            mode = (mode & !who_mask) | add_bits;
            // Also clear setuid/setgid/sticky for the relevant who.
            if whos.is_empty() || whos.contains('u') || whos.contains('a') {
                mode &= !0o4000;
            }
            if whos.contains('g') || whos.is_empty() || whos.contains('a') {
                mode &= !0o2000;
            }
            if whos.is_empty() || whos.contains('o') || whos.contains('a') {
                mode &= !0o1000;
            }
            mode |= special_add;
        }
        _ => unreachable!(),
    }
    Ok(mode & 0o7777)
}

/// `chmod` command: change mode (octal or symbolic) with auto-backup.
/// Accepts one or more target paths; a single snapshot covers the whole batch.
pub fn cmd_chmod(
    mode_spec: &str,
    paths_in: &[String],
    recursive: bool,
    capture_acl: bool,
    reference: Option<&str>,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    if paths_in.is_empty() {
        return Err(PmError::Other("chmod: no target paths".into()));
    }
    // Resolve reference mode once up front (if any).
    let ref_mode: Option<u32> = if let Some(r) = reference {
        let rp = resolve_path(r)?;
        let md = fs::metadata(&rp).map_err(|e| PmError::InsufficientPrivileges {
            path: rp.clone(),
            reason: e.to_string(),
        })?;
        Some(md.permissions().mode() & 0o7777)
    } else {
        None
    };
    let (resolved_targets, paths) = expand_targets(paths_in, recursive, exclude)?;
    if paths.is_empty() {
        eprintln!("chmod: no paths left after --exclude");
        return Ok(());
    }

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, capture_acl);
            let target_str = resolved_targets
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "chmod".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(target_str),
                    access: Some(
                        ref_mode
                            .map(|m| format!("ref:{m:04o}"))
                            .unwrap_or_else(|| mode_spec.to_string()),
                    ),
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                },
            )?;
            println!("backup: {bid}");
        }
        let (c, u, f) = apply_chmod_to_paths(&paths, mode_spec, ref_mode, dry_run)?;
        let c_s = c.to_string();
        let u_s = u.to_string();
        let f_s = f.to_string();
        let segs: Vec<(&str, &str)> = vec![
            (
                c_s.as_str(),
                if dry_run { "would change" } else { "changed" },
            ),
            (u_s.as_str(), "unchanged"),
            (if f > 0 { f_s.as_str() } else { "" }, "failed"),
        ];
        eprintln!("{}", summary_line(&segs));
        if f > 0 {
            Err(PmError::Other(format!("{f} path(s) failed")))
        } else {
            Ok(())
        }
    })
}

/// `chown` command: change owner and/or group with auto-backup.
/// Accepts one or more target paths.
pub fn cmd_chown(
    spec: &str,
    paths_in: &[String],
    recursive: bool,
    capture_acl: bool,
    reference: Option<&str>,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    if paths_in.is_empty() {
        return Err(PmError::Other("chown: no target paths".into()));
    }
    let (new_uid, new_gid) = resolve_chown_target(spec, reference)?;
    let (resolved_targets, paths) = expand_targets(paths_in, recursive, exclude)?;
    if paths.is_empty() {
        eprintln!("chown: no paths left after --exclude");
        return Ok(());
    }

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, capture_acl);
            let target_str = resolved_targets
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "chown".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(target_str),
                    access: Some(if reference.is_some() {
                        format!(
                            "ref:{}:{}",
                            new_uid.map(|u| u.to_string()).unwrap_or("-".into()),
                            new_gid.map(|g| g.to_string()).unwrap_or("-".into())
                        )
                    } else {
                        spec.to_string()
                    }),
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                },
            )?;
            println!("backup: {bid}");
        }
        let (c, u, f) = apply_chown_to_paths(&paths, new_uid, new_gid, dry_run)?;
        let c_s = c.to_string();
        let u_s = u.to_string();
        let f_s = f.to_string();
        let segs: Vec<(&str, &str)> = vec![
            (
                c_s.as_str(),
                if dry_run { "would change" } else { "changed" },
            ),
            (u_s.as_str(), "unchanged"),
            (if f > 0 { f_s.as_str() } else { "" }, "failed"),
        ];
        eprintln!("{}", summary_line(&segs));
        if f > 0 {
            Err(PmError::Other(format!("{f} path(s) failed")))
        } else {
            Ok(())
        }
    })
}

fn parse_chown_spec(spec: &str) -> Result<(Option<u32>, Option<u32>)> {
    if spec.is_empty() {
        return Err(PmError::Other("empty chown spec".into()));
    }
    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid = if user_part.is_empty() {
        None
    } else if let Ok(n) = user_part.parse::<u32>() {
        Some(n)
    } else {
        Some(lookup_user(user_part)?.uid.as_raw())
    };
    let gid = match group_part {
        None => None,
        Some(g) if g.is_empty() => None,
        Some(g) => {
            if let Ok(n) = g.parse::<u32>() {
                Some(n)
            } else {
                Some(lookup_group(g)?.gid.as_raw())
            }
        }
    };
    Ok((uid, gid))
}

// Keep imports alive
#[allow(dead_code)]
fn _keep() {
    let _ = Path::new("/");
}

/// `copy-perms SRC DST`: copy mode + owner + group (+ optionally ACLs) from
/// SRC to DST, with an auto-snapshot of DST. When `recursive` is set, DST must
/// be a directory and every entry under it receives SRC's mode / ownership.
pub fn cmd_copy_perms(
    src: &str,
    dst: &str,
    include_acl: bool,
    recursive: bool,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    use nix::unistd::{Gid, Uid};
    let src_path = resolve_path(src)?;
    let dst_path = resolve_path(dst)?;
    crate::locks::ensure_not_locked(&dst_path)?;
    let src_md = fs::symlink_metadata(&src_path).map_err(|e| PmError::InsufficientPrivileges {
        path: src_path.clone(),
        reason: e.to_string(),
    })?;
    let src_mode = src_md.permissions().mode() & 0o7777;
    let src_uid = src_md.uid();
    let src_gid = src_md.gid();
    let src_user = uid_to_name(Uid::from_raw(src_uid));
    let src_group = gid_to_name(Gid::from_raw(src_gid));
    let src_has_acl = crate::acl::has_extended_acl(&src_path);

    let stdout_tty = is_terminal::is_terminal(std::io::stdout());

    // ── Source profile header (TTY only) ─────────────────────────────
    if stdout_tty {
        let marker = if dry_run { "  [DRY RUN]" } else { "" };
        println!(
            "\n  {}  {}",
            paint(Style::Label, "source:"),
            paint(Style::Primary, &src_path.display().to_string())
        );
        println!(
            "           mode  {:04o} {}",
            src_mode,
            paint(
                Style::Label,
                &crate::render::format_symbolic(src_mode, src_md.is_dir(), false)
            )
        );
        println!(
            "           owner {}:{} (uid {} : gid {})",
            paint(Style::User, &src_user),
            paint(Style::Group, &src_group),
            src_uid,
            src_gid
        );
        println!(
            "           acl   {}",
            paint(
                Style::Label,
                if src_has_acl {
                    "present (will be copied)"
                } else {
                    "none"
                }
            )
        );
        println!(
            "\n  {}  {}{}",
            paint(Style::Label, "target:"),
            paint(Style::Primary, &dst_path.display().to_string()),
            paint(Style::WarnMajor, marker)
        );
    }

    // Collect targets (dst + optionally children), honoring --exclude.
    let mut targets: Vec<std::path::PathBuf> = Vec::new();
    if !exclude.is_excluded(&dst_path) {
        targets.push(dst_path.clone());
    }
    if recursive {
        for entry in walkdir::WalkDir::new(&dst_path)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let ep = entry.path().to_path_buf();
            if exclude.is_excluded(&ep) {
                continue;
            }
            targets.push(ep);
        }
    }
    if targets.is_empty() {
        eprintln!("copy-perms: no paths left after --exclude");
        return Ok(());
    }

    with_lock(|| {
        let snap_entries = snapshot_with_acl(&targets, include_acl);
        let mut backup_id: Option<String> = None;
        if !dry_run {
            let bid = save_backup(
                snap_entries,
                Operation {
                    op_type: "copy-perms".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(dst_path.display().to_string()),
                    access: Some(format!("from:{}", src_path.display())),
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                },
            )?;
            backup_id = Some(bid);
        }

        if dry_run {
            if stdout_tty {
                println!();
                let max_show = 8;
                for (i, t) in targets.iter().enumerate() {
                    if i >= max_show {
                        println!(
                            "  {} ... and {} more",
                            paint(Style::Separator, "…"),
                            targets.len() - max_show
                        );
                        break;
                    }
                    println!(
                        "  [dry-run] {}  {}",
                        paint(
                            Style::Label,
                            &format!("chmod {src_mode:04o} chown {src_user}:{src_group}")
                        ),
                        paint(Style::Primary, &t.display().to_string())
                    );
                }
                if include_acl && src_has_acl {
                    println!(
                        "  [dry-run] {}",
                        paint(Style::Label, "copy ACL from source to each target")
                    );
                }
            } else {
                for t in &targets {
                    println!(
                        "[dry-run] chmod {src_mode:o} {}  (from {})",
                        t.display(),
                        src_path.display()
                    );
                    println!("[dry-run] lchown {src_uid}:{src_gid} {}", t.display());
                }
            }
            return Ok(());
        }

        // Apply mode + ownership.
        let mut changed = 0usize;
        for t in &targets {
            let tmd = fs::symlink_metadata(t).map_err(|e| PmError::InsufficientPrivileges {
                path: t.clone(),
                reason: e.to_string(),
            })?;
            if !tmd.file_type().is_symlink() {
                fs::set_permissions(t, fs::Permissions::from_mode(src_mode)).map_err(|e| {
                    PmError::InsufficientPrivileges {
                        path: t.clone(),
                        reason: e.to_string(),
                    }
                })?;
            }
            lchown(t, Some(src_uid), Some(src_gid)).map_err(|e| {
                PmError::InsufficientPrivileges {
                    path: t.clone(),
                    reason: e.to_string(),
                }
            })?;
            changed += 1;
        }

        if include_acl {
            let src_acl = crate::acl::get_acl(&src_path)?;
            for t in &targets {
                match &src_acl {
                    Some(text) => {
                        crate::acl::restore_acl(t, Some(text), None, false)?;
                    }
                    None => {
                        let _ = crate::acl::acl_strip(t, false, false);
                    }
                }
            }
        }

        if let Some(bid) = &backup_id {
            println!(
                "\n{}  {}",
                paint(Style::Label, "backup:"),
                paint(Style::Primary, bid)
            );
        }
        let n_s = changed.to_string();
        let segs: Vec<(&str, &str)> = vec![(
            n_s.as_str(),
            if changed == 1 {
                "path updated"
            } else {
                "paths updated"
            },
        )];
        eprintln!("{}", summary_line(&segs));
        Ok(())
    })
}
