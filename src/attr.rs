//! `attr`: thin wrapper around `chattr`/`lsattr` for immutable/append-only flags.

use crate::errors::{PmError, Result};
use crate::helpers::resolve_path;
use std::process::Command;

fn which(cmd: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null 2>&1"))
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(PmError::Other(format!(
            "`{cmd}` not found; install `e2fsprogs` (provides chattr/lsattr)"
        ))),
    }
}

pub fn cmd_attr_show(path: &str) -> Result<()> {
    which("lsattr")?;
    let p = resolve_path(path)?;
    let out = Command::new("lsattr")
        .arg("-d")
        .arg(&p)
        .output()
        .map_err(|e| PmError::Other(format!("lsattr: {e}")))?;
    if !out.status.success() {
        return Err(PmError::Other(format!(
            "lsattr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn chattr(path: &str, flag: &str) -> Result<()> {
    which("chattr")?;
    crate::locks::ensure_not_locked(&resolve_path(path)?)?;
    let out = Command::new("chattr")
        .arg(flag)
        .arg(path)
        .output()
        .map_err(|e| PmError::Other(format!("chattr: {e}")))?;
    if !out.status.success() {
        return Err(PmError::Other(format!(
            "chattr {flag} {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    println!("chattr {flag} {path}");
    Ok(())
}

pub fn cmd_attr_set_immutable(path: &str) -> Result<()> {
    chattr(path, "+i")
}
pub fn cmd_attr_clear_immutable(path: &str) -> Result<()> {
    chattr(path, "-i")
}
pub fn cmd_attr_set_append(path: &str) -> Result<()> {
    chattr(path, "+a")
}
pub fn cmd_attr_clear_append(path: &str) -> Result<()> {
    chattr(path, "-a")
}
