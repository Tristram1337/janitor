//! Built-in presets for common permission patterns.

use crate::chperm::cmd_chmod;
use crate::errors::{PmError, Result};

pub const PRESETS: &[(&str, &str, &str)] = &[
    ("private", "700", "owner only"),
    ("private-dir", "700", "directory visible to owner only"),
    (
        "private-file",
        "600",
        "file readable/writable by owner only",
    ),
    (
        "group-shared",
        "770",
        "rwx for owner and group, none for other",
    ),
    ("group-read", "750", "rwx owner, rx group, none other"),
    ("public-read", "755", "rwx owner, rx group, rx other"),
    ("public-file", "644", "rw owner, r group, r other"),
    (
        "sticky-dir",
        "1777",
        "world-writable with sticky bit (/tmp style)",
    ),
    (
        "setgid-dir",
        "2775",
        "group-shared dir with setgid (new files inherit group)",
    ),
    ("secret", "400", "read-only for owner, nobody else"),
    (
        "secret-dir",
        "500",
        "directory readable/traversable by owner only, read-only",
    ),
    (
        "exec-only",
        "711",
        "owner rwx, others may traverse but not list",
    ),
    ("ssh-key", "600", "private SSH key / secret file (owner rw)"),
    (
        "ssh-dir",
        "700",
        "SSH / secret directory (owner rwx, nobody else)",
    ),
    (
        "config",
        "640",
        "service config readable by owner + group (rw/r/-)",
    ),
    ("log-file", "640", "log file (owner rw, group r, other -)"),
    (
        "systemd-unit",
        "644",
        "systemd unit / service file (rw/r/r)",
    ),
    (
        "read-only",
        "444",
        "read-only for everyone (legal-hold style)",
    ),
    ("no-access", "000", "no access for anyone (placeholder)"),
];

pub fn cmd_list_presets() {
    println!("{:<15}  {:<6}  {}", "name", "mode", "description");
    println!("{}", "-".repeat(70));
    for (name, mode, desc) in PRESETS {
        println!("{name:<15}  {mode:<6}  {desc}");
    }
}

pub fn cmd_apply_preset(
    name: &str,
    paths: &[String],
    recursive: bool,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    let preset = PRESETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .ok_or_else(|| PmError::Other(format!("unknown preset: {name:?}  (try `presets`)")))?;
    println!("applying preset {:?} → mode {}", preset.0, preset.1);
    cmd_chmod(preset.1, paths, recursive, false, None, exclude, dry_run)
}

/// Look up a preset by name and return its octal mode string.
/// Used by `batch` / `policy apply` which manage their own snapshot.
pub fn resolve_preset(name: &str) -> Result<&'static str> {
    PRESETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, m, _)| *m)
        .ok_or_else(|| PmError::Other(format!("unknown preset: {name:?}  (try `presets`)")))
}
