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
/// Schema: `pm_<slug>_<hash8>` where:
///   * `slug` is a short lowercase snippet of the last 1–2 path segments
///     (≤ 20 chars), kept purely for operator readability;
///   * `hash8` is the lower 32 bits of a deterministic FNV-1a 64-bit
///     hash of the **absolute canonical path**, rendered as 8 hex chars.
///
/// The hash disambiguator prevents the v0.1.0 collision bug where two
/// different paths sharing the first 28 chars of their slug collapsed
/// to the same managed group (§3.12 — caused a silent access-bypass).
/// Total length is ≤ 32 chars (Linux `NAME_MAX` for group names).
///
/// Examples:
///   `/srv/project`                              → `pm_srv_project_1a2b3c4d`
///   `/home/u/a/b/c/jwt.secret`                  → `pm_c_jwt_a1b2c3d4`
///   `/home/u/a/b/d/schema.sql` (same prefix)    → `pm_d_schema_9f8e7d6c`
///     (different final hash => different group => no collision)
pub fn default_group_name(target: &Path) -> String {
    let base = if target.is_file() {
        target.parent().unwrap_or(target)
    } else {
        target
    };

    // Build a deterministic absolute-path key for the hash. We use
    // components() so `./a` and `a` collapse identically after
    // canonicalisation at the caller; here we just make a byte-stable
    // form of whatever Path we were given.
    let key: String = base
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/");
    let hash8 = fnv1a_hex8(key.as_bytes());

    // Human-readable slug from last two non-trivial segments.
    let parts: Vec<&str> = base
        .components()
        .filter_map(|c| {
            let s = c.as_os_str().to_str()?;
            if s == "/" || s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect();
    let tail = if parts.len() >= 2 {
        format!("{}_{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else if parts.len() == 1 {
        parts[0].to_string()
    } else {
        "root".to_string()
    };
    let slug: String = tail
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Cap slug at 20 chars so total name `pm_<slug>_<8hex>` ≤ 32.
    let slug = if slug.len() > 20 {
        slug[..20].trim_end_matches(['_', '-']).to_string()
    } else {
        slug
    };
    let slug = if slug.is_empty() { "root".to_string() } else { slug };
    format!("pm_{slug}_{hash8}")
}

/// Deterministic FNV-1a 64-bit hash, rendered as lower 32 bits in 8 hex
/// chars. Stable across Rust versions (unlike `std::hash::DefaultHasher`)
/// and across platforms. Not cryptographic — used purely as a collision
/// disambiguator, not a security primitive.
fn fnv1a_hex8(bytes: &[u8]) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h: u64 = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{:08x}", (h as u32))
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

    // ── §3.12 regression: pm_ naming collision must not recur ──────────

    /// The v0.1.0 exploit: two different paths sharing the first 28
    /// chars of their slug collapsed to the same `pm_<trunc>` name.
    /// With the hash disambiguator they must differ.
    #[test]
    fn group_names_differ_for_long_shared_prefix() {
        let a = default_group_name(Path::new(
            "/srv/acme/engineering/src/backend/auth/session/jwt.secret",
        ));
        let b = default_group_name(Path::new(
            "/srv/acme/engineering/src/backend/db/schema.sql",
        ));
        assert_ne!(a, b, "collision regression: {a} == {b}");
    }

    /// Generator must be deterministic: same path → same name across
    /// invocations. Required for restore/undo to find the right group.
    #[test]
    fn group_name_is_deterministic() {
        let p = Path::new("/srv/acme/engineering/docs");
        assert_eq!(default_group_name(p), default_group_name(p));
    }

    /// All generated names must fit Linux's 32-char group name limit.
    #[test]
    fn group_name_respects_32_char_limit() {
        for p in [
            "/",
            "/srv",
            "/srv/acme",
            "/srv/acme/engineering/src/backend/auth/session/jwt.secret",
            "/home/user1/a/b/c/d/e/f/g/h/i/j/k/very/deep/path/to/file.txt",
        ] {
            let n = default_group_name(Path::new(p));
            assert!(n.len() <= 32, "{p:?} -> {n:?} ({} chars)", n.len());
            assert!(n.starts_with("pm_"), "{n:?}");
        }
    }

    /// Hash is path-sensitive: a one-char change yields a different
    /// hash (extremely likely for FNV-1a).
    #[test]
    fn hash_changes_with_path() {
        let a = default_group_name(Path::new("/srv/project_a"));
        let b = default_group_name(Path::new("/srv/project_b"));
        assert_ne!(a, b);
    }
}
