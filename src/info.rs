//! `janitor info PATH`: one-shot summary of a path's permissions.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::time::{Duration, UNIX_EPOCH};

use crate::acl::get_acl;
use crate::errors::Result;
use crate::users::{lookup_user, user_gids};

/// Convert a 4-digit mode into the familiar `rwxr-sr-t` 10-char string
/// (no file-type prefix). Handles setuid/setgid/sticky bits.
fn symbolic_mode(mode: u32, is_dir: bool) -> String {
    let mut s = String::with_capacity(9);
    let r = |bit: u32| if mode & bit != 0 { 'r' } else { '-' };
    let w = |bit: u32| if mode & bit != 0 { 'w' } else { '-' };
    // owner
    s.push(r(0o400));
    s.push(w(0o200));
    s.push(match (mode & 0o100 != 0, mode & 0o4000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    // group
    s.push(r(0o040));
    s.push(w(0o020));
    s.push(match (mode & 0o010 != 0, mode & 0o2000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    // other
    s.push(r(0o004));
    s.push(w(0o002));
    s.push(match (mode & 0o001 != 0, mode & 0o1000 != 0, is_dir) {
        (true, true, _) => 't',
        (false, true, _) => 'T',
        (true, false, _) => 'x',
        (false, false, _) => '-',
    });
    s
}

fn file_type_char(md: &fs::Metadata) -> char {
    let ft = md.file_type();
    if ft.is_symlink() {
        'l'
    } else if ft.is_dir() {
        'd'
    } else if ft.is_fifo() {
        'p'
    } else if ft.is_socket() {
        's'
    } else if ft.is_block_device() {
        'b'
    } else if ft.is_char_device() {
        'c'
    } else {
        '-'
    }
}

fn user_name(uid: u32) -> String {
    use nix::unistd::{Uid, User};
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| format!("#{uid}"))
}

fn group_name(gid: u32) -> String {
    use nix::unistd::{Gid, Group};
    Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| format!("#{gid}"))
}

fn format_mtime(md: &fs::Metadata) -> String {
    let secs = md.mtime() as u64;
    let dur = Duration::from_secs(secs);
    let tm = UNIX_EPOCH + dur;
    // Simple UTC ISO-8601 (YYYY-MM-DD HH:MM:SS).
    let t = tm
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Naive conversion without chrono: days/seconds math.
    let days = (t / 86400) as i64;
    let hms = (t % 86400) as u32;
    let (h, m, s) = (hms / 3600, (hms / 60) % 60, hms % 60);
    let (year, mon, day) = days_to_ymd(days);
    format!("{year:04}-{mon:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Civil days since 1970-01-01 → (year, month, day). Howard Hinnant algorithm.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (if m <= 2 { y + 1 } else { y }) as i32;
    (year, m, d)
}

/// Effective (read, write, execute/traverse) for `username` on this inode.
fn effective_for_user(md: &fs::Metadata, username: &str) -> Result<(bool, bool, bool)> {
    let u = lookup_user(username)?;
    let uid = u.uid.as_raw();
    let gids: std::collections::HashSet<u32> = user_gids(username)?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    let mode = md.mode() & 0o7777;
    if uid == 0 {
        let is_dir = md.is_dir();
        return Ok((true, true, is_dir || (mode & 0o111 != 0)));
    }
    let triad = if uid == md.uid() {
        (mode >> 6) & 0o7
    } else if gids.contains(&md.gid()) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    Ok((triad & 0o4 != 0, triad & 0o2 != 0, triad & 0o1 != 0))
}

pub fn cmd_info(path: &str, for_user: Option<&str>) -> Result<()> {
    // Do not canonicalize: we want to inspect symlinks themselves.
    let p = {
        let expanded = if let Some(stripped) = path.strip_prefix('~') {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            std::path::PathBuf::from(format!("{home}{stripped}"))
        } else {
            std::path::PathBuf::from(path)
        };
        if expanded.symlink_metadata().is_err() {
            return Err(crate::errors::PmError::PathNotFound(expanded));
        }
        expanded
    };
    let md = fs::symlink_metadata(&p).map_err(|e| crate::errors::PmError::Other(e.to_string()))?;
    let mode = md.permissions().mode() & 0o7777;
    let is_dir = md.is_dir();
    let ft = file_type_char(&md);

    println!("path:     {}", p.display());
    let kind = match ft {
        'd' => "directory",
        'l' => "symlink",
        'p' => "fifo",
        's' => "socket",
        'b' => "block device",
        'c' => "char device",
        _ => "regular file",
    };
    println!("type:     {kind}");
    if ft == 'l' {
        if let Ok(target) = fs::read_link(&p) {
            println!("target:   {}", target.display());
        }
    }
    println!("owner:    {} ({})", user_name(md.uid()), md.uid());
    println!("group:    {} ({})", group_name(md.gid()), md.gid());
    println!(
        "mode:     {mode:04o}  {}{}",
        ft,
        symbolic_mode(mode, is_dir)
    );

    // Special-bit line (always printed; "none" if no special bits).
    let mut special: Vec<&str> = Vec::new();
    if mode & 0o4000 != 0 {
        special.push("setuid");
    }
    if mode & 0o2000 != 0 {
        special.push("setgid");
    }
    if mode & 0o1000 != 0 {
        special.push("sticky");
    }
    println!(
        "special:  {}",
        if special.is_empty() {
            "none".to_string()
        } else {
            special.join(", ")
        }
    );
    if ft == '-' || ft == 'd' {
        println!("size:     {} bytes", md.len());
    }
    println!("mtime:    {}", format_mtime(&md));

    // ACLs (skipped for symlinks: ACLs apply to the target file).
    if ft != 'l' {
        match get_acl(&p) {
            Ok(Some(acl)) => {
                println!("acl:");
                for line in acl.lines() {
                    if line.trim().is_empty() || line.starts_with('#') {
                        continue;
                    }
                    println!("  {line}");
                }
            }
            Ok(None) => println!("acl:      none"),
            Err(_) => println!("acl:      (unavailable)"),
        }
    }

    // Effective access for a specific user.
    if let Some(user) = for_user {
        let (r, w, x) = effective_for_user(&md, user)?;
        let bits = format!(
            "{}{}{}",
            if r { 'r' } else { '-' },
            if w { 'w' } else { '-' },
            if x { 'x' } else { '-' }
        );
        println!(
            "access:   {user} → {bits}  (on this inode; use `who-can` for parent-chain evaluation)"
        );
    }

    Ok(())
}
