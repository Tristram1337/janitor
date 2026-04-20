//! POSIX ACL support via `getfacl` / `setfacl` shell-outs.
//!
//! We shell out (rather than using libacl bindings) to keep the dep surface
//! minimal and match the approach used for group management (`gpasswd`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::errors::{PmError, Result};

const GETFACL: &str = "/usr/bin/getfacl";
const SETFACL: &str = "/usr/bin/setfacl";

/// Return true if `setfacl` / `getfacl` binaries are installed.
pub fn acl_available() -> bool {
    Path::new(GETFACL).exists() && Path::new(SETFACL).exists()
}

/// Get the access ACL of a path in canonical (compact) form.
/// Returns None if ACL tooling not installed or only the base mode is present.
pub fn get_acl(path: &Path) -> Result<Option<String>> {
    if !acl_available() {
        return Ok(None);
    }
    // -c: no header, --absolute-names: don't strip leading /
    let out = Command::new(GETFACL)
        .args(["-c", "--absolute-names", "--"])
        .arg(path)
        .output()
        .map_err(|e| PmError::Other(format!("getfacl failed: {e}")))?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// Get the default ACL of a directory (inherited by new children).
pub fn get_default_acl(path: &Path) -> Result<Option<String>> {
    if !acl_available() {
        return Ok(None);
    }
    let out = Command::new(GETFACL)
        .args(["-cd", "--absolute-names", "--"])
        .arg(path)
        .output()
        .map_err(|e| PmError::Other(format!("getfacl -d failed: {e}")))?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    // Filter out lines that aren't actual ACL entries.
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .collect();
    if lines.is_empty() {
        Ok(None)
    } else {
        Ok(Some(lines.join("\n")))
    }
}

/// Restore both access and default ACL from captured text.
/// Uses `setfacl --set-file=-` which replaces the ACL completely.
pub fn restore_acl(
    path: &Path,
    acl_text: Option<&str>,
    default_acl_text: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    if !acl_available() {
        return Ok(());
    }
    if let Some(text) = acl_text {
        apply_acl_text(path, text, false, dry_run)?;
    }
    if let Some(text) = default_acl_text {
        apply_acl_text(path, text, true, dry_run)?;
    }
    Ok(())
}

fn apply_acl_text(path: &Path, text: &str, is_default: bool, dry_run: bool) -> Result<()> {
    if dry_run {
        let tag = if is_default { "-d " } else { "" };
        println!("[dry-run] setfacl {tag}--set-file=- {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical"); // no follow symlinks
    if is_default {
        cmd.arg("-d");
    }
    cmd.arg("--set-file=-");
    cmd.arg("--");
    cmd.arg(path);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| PmError::Other(format!("setfacl spawn: {e}")))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| PmError::Other("setfacl stdin".into()))?;
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| PmError::Other(format!("setfacl write: {e}")))?;
        if !text.ends_with('\n') {
            stdin.write_all(b"\n").ok();
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| PmError::Other(format!("setfacl wait: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(PmError::Other(format!(
            "setfacl failed on {}: {}",
            path.display(),
            err.trim()
        )));
    }
    Ok(())
}

/// Modify ACL entries: `setfacl -m <spec>` (merge).
pub fn acl_modify(path: &Path, spec: &str, recursive: bool, dry_run: bool) -> Result<()> {
    if !acl_available() {
        return Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package".into(),
        ));
    }
    if dry_run {
        let r = if recursive { "-R " } else { "" };
        println!("[dry-run] setfacl {r}-m {spec} {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical");
    if recursive {
        cmd.arg("-R");
    }
    cmd.args(["-m", spec, "--"]);
    cmd.arg(path);
    let status = cmd
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -m {spec} failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Remove ACL entries: `setfacl -x <spec>` (entry removal).
pub fn acl_remove(path: &Path, spec: &str, recursive: bool, dry_run: bool) -> Result<()> {
    if !acl_available() {
        return Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package".into(),
        ));
    }
    if dry_run {
        let r = if recursive { "-R " } else { "" };
        println!("[dry-run] setfacl {r}-x {spec} {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical");
    if recursive {
        cmd.arg("-R");
    }
    cmd.args(["-x", spec, "--"]);
    cmd.arg(path);
    let status = cmd
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -x {spec} failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Strip all ACLs (keep only base mode).
pub fn acl_strip(path: &Path, recursive: bool, dry_run: bool) -> Result<()> {
    if !acl_available() {
        return Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package".into(),
        ));
    }
    if dry_run {
        let r = if recursive { "-R " } else { "" };
        println!("[dry-run] setfacl {r}-b {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical");
    if recursive {
        cmd.arg("-R");
    }
    cmd.args(["-b", "--"]);
    cmd.arg(path);
    let status = cmd
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -b failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Check if a path has any non-trivial ACL entries beyond the base mode.
pub fn has_extended_acl(path: &Path) -> bool {
    match get_acl(path) {
        Ok(Some(text)) => text.lines().any(|l| {
            let t = l.trim();
            // Trivial entries are user::, group::, other::. Anything else = extended.
            if t.is_empty() || t.starts_with('#') {
                return false;
            }
            !(t.starts_with("user::") || t.starts_with("group::") || t.starts_with("other::"))
        }),
        _ => false,
    }
}
