//! Small path utilities shared across commands.

use std::path::{Path, PathBuf};

use crate::errors::{PmError, Result};
use crate::types::AccessBits;

/// Parse "r", "rw", "rx", "rwx" etc. into permission bits (0..7).
pub fn parse_access(s: &str) -> Result<AccessBits> {
    let s = s.to_lowercase();
    if s.is_empty() || s.chars().any(|c| !matches!(c, 'r' | 'w' | 'x')) {
        return Err(PmError::BadAccess(s));
    }
    let mut bits: u32 = 0;
    if s.contains('r') {
        bits |= 0o4;
    }
    if s.contains('w') {
        bits |= 0o2;
    }
    if s.contains('x') {
        bits |= 0o1;
    }
    Ok(AccessBits(bits))
}

/// Resolve a path: expand `~`, canonicalize, fail if missing.
pub fn resolve_path(p: &str) -> Result<PathBuf> {
    let expanded = if p.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        PathBuf::from(p.replacen('~', &home, 1))
    } else {
        PathBuf::from(p)
    };
    expanded
        .canonicalize()
        .map_err(|_| PmError::PathNotFound(expanded))
}

/// Return every path segment from (but not including) `stop_at` down to
/// and including `target`, in top-down order.
///
/// For `/home/user1/a/b/file.txt` with stop_at=`/`:
///   `[/home, /home/user1, /home/user1/a, /home/user1/a/b, /home/user1/a/b/file.txt]`
pub fn path_chain(target: &Path, stop_at: &Path) -> Vec<PathBuf> {
    let mut segs = Vec::new();
    let mut cur = target.to_path_buf();
    while cur != stop_at && cur.parent().is_some() && cur != cur.parent().unwrap().to_path_buf() {
        segs.push(cur.clone());
        cur = cur.parent().unwrap().to_path_buf();
    }
    segs.reverse();
    segs
}

/// Validate a group name matches Linux conventions: [a-z_][a-z0-9_-]{0,31}
pub fn validate_group_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        return Err(PmError::InvalidGroupName(name.to_string()));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() && first != '_' {
        return Err(PmError::InvalidGroupName(name.to_string()));
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '-' {
            return Err(PmError::InvalidGroupName(name.to_string()));
        }
    }
    Ok(())
}

/// Derive a stable, human-readable managed group name for a target path.
///
/// For files, we use the parent directory so many files in one dir
/// share the same managed group.
///
///   `/srv/project`                   → `pm_srv_project`
///   `/home/user1/a/b/c/d/file.txt`  → `pm_user1_a_b_c_d`
pub fn default_group_name(target: &Path) -> String {
    let base = if target.is_file() {
        target.parent().unwrap_or(target)
    } else {
        target
    };
    let parts: Vec<&str> = base
        .components()
        .filter_map(|c| {
            let s = c.as_os_str().to_str()?;
            if s == "/" || s == "home" || s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect();
    let slug: String = parts.join("_");
    let slug: String = slug
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    let slug = if slug.len() > 28 {
        slug[..28].trim_end_matches(['_', '-']).to_string()
    } else {
        slug
    };
    if slug.is_empty() {
        "pm_root".to_string()
    } else {
        format!("pm_{slug}")
    }
}

/// Read extra paths from stdin (NUL-separated if `stdin0`) and/or a file
/// (newline-separated; `-` means stdin). Extends `base` with them.
pub fn read_extra_paths(
    base: &mut Vec<String>,
    stdin0: bool,
    from_file: Option<&str>,
) -> Result<()> {
    use std::io::Read;
    if stdin0 {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| PmError::Other(format!("stdin: {e}")))?;
        for chunk in buf.split(|b| *b == 0) {
            if chunk.is_empty() {
                continue;
            }
            base.push(String::from_utf8_lossy(chunk).to_string());
        }
    }
    if let Some(f) = from_file {
        let text = if f == "-" {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| PmError::Other(format!("stdin: {e}")))?;
            s
        } else {
            std::fs::read_to_string(f).map_err(|e| PmError::Other(format!("read {f}: {e}")))?
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            base.push(line.to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_access() {
        assert_eq!(parse_access("r").unwrap().0, 0o4);
        assert_eq!(parse_access("rw").unwrap().0, 0o6);
        assert_eq!(parse_access("rwx").unwrap().0, 0o7);
        assert_eq!(parse_access("rx").unwrap().0, 0o5);
        assert!(parse_access("").is_err());
        assert!(parse_access("z").is_err());
        assert!(parse_access("rz").is_err());
    }

    #[test]
    fn test_path_chain() {
        let chain = path_chain(Path::new("/home/user1/a/b/file.txt"), Path::new("/"));
        assert_eq!(
            chain,
            vec![
                PathBuf::from("/home"),
                PathBuf::from("/home/user1"),
                PathBuf::from("/home/user1/a"),
                PathBuf::from("/home/user1/a/b"),
                PathBuf::from("/home/user1/a/b/file.txt"),
            ]
        );
    }

    #[test]
    fn test_validate_group_name() {
        assert!(validate_group_name("pm_test").is_ok());
        assert!(validate_group_name("pm_srv_project").is_ok());
        assert!(validate_group_name("a-b_c").is_ok());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name("1bad").is_err());
        assert!(validate_group_name("has space").is_err());
        assert!(validate_group_name(&"a".repeat(33)).is_err());
    }
}
