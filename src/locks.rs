//! Persistent lock list: paths that janitor refuses to mutate.
//!
//! Stored as a newline-delimited file (`locks.txt`) in the backup directory.
//! Each line is `PATH\tREASON` (reason may be empty). A directory lock implies
//! every descendant is locked.

use crate::errors::{PmError, Result};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

fn locks_file() -> PathBuf {
    crate::config::backup_root().join("locks.txt")
}

#[derive(Debug, Clone)]
pub struct LockEntry {
    pub path: PathBuf,
    pub reason: String,
}

pub fn load() -> Result<Vec<LockEntry>> {
    let p = locks_file();
    if !p.exists() {
        return Ok(Vec::new());
    }
    let f = fs::File::open(&p).map_err(|e| PmError::Other(format!("open locks: {e}")))?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
        let line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (path, reason) = match line.split_once('\t') {
            Some((p, r)) => (p.to_string(), r.to_string()),
            None => (line, String::new()),
        };
        out.push(LockEntry {
            path: PathBuf::from(path),
            reason,
        });
    }
    Ok(out)
}

fn save(entries: &[LockEntry]) -> Result<()> {
    let dir = crate::config::backup_root();
    fs::create_dir_all(&dir).map_err(|e| PmError::Other(format!("mkdir backup: {e}")))?;
    let p = locks_file();
    let tmp = p.with_extension("txt.tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|e| PmError::Other(format!("write locks: {e}")))?;
    for e in entries {
        writeln!(f, "{}\t{}", e.path.display(), e.reason)
            .map_err(|e| PmError::Other(format!("write locks: {e}")))?;
    }
    f.sync_all().ok();
    drop(f);
    fs::rename(&tmp, &p).map_err(|e| PmError::Other(format!("rename locks: {e}")))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn add(path: &Path, reason: Option<&str>) -> Result<()> {
    let mut locks = load()?;
    if locks.iter().any(|l| l.path == path) {
        return Err(PmError::Other(format!(
            "already locked: {}",
            path.display()
        )));
    }
    locks.push(LockEntry {
        path: path.to_path_buf(),
        reason: reason.unwrap_or("").to_string(),
    });
    save(&locks)
}

pub fn remove(path: &Path) -> Result<()> {
    let mut locks = load()?;
    let len0 = locks.len();
    locks.retain(|l| l.path != path);
    if locks.len() == len0 {
        return Err(PmError::Other(format!("not locked: {}", path.display())));
    }
    save(&locks)
}

/// Error out if `path` or any ancestor directory is locked.
pub fn ensure_not_locked(path: &Path) -> Result<()> {
    let locks = load().unwrap_or_default();
    for l in &locks {
        if path == l.path || path.starts_with(&l.path) {
            let r = if l.reason.is_empty() {
                String::new()
            } else {
                format!(" ({})", l.reason)
            };
            return Err(PmError::Other(format!(
                "path is locked by `janitor lock`: {}{r}",
                l.path.display()
            )));
        }
    }
    Ok(())
}
