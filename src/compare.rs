//! `compare A B`: report differences in mode/owner/group/ACL.

use crate::acl::has_extended_acl;
use crate::errors::{PmError, Result};
use crate::helpers::resolve_path;
use nix::unistd::{Gid, Uid};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Eq, PartialEq)]
struct Snap {
    mode: u32,
    uid: u32,
    gid: u32,
    acl: bool,
    kind: char,
}

fn snap(p: &Path) -> Option<Snap> {
    let md = fs::symlink_metadata(p).ok()?;
    let kind = if md.file_type().is_symlink() {
        'l'
    } else if md.is_dir() {
        'd'
    } else {
        'f'
    };
    Some(Snap {
        mode: md.permissions().mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        acl: has_extended_acl(p),
        kind,
    })
}

fn fmt_snap(s: &Snap) -> String {
    format!(
        "{} mode={:04o} owner={} group={}{}",
        s.kind,
        s.mode,
        crate::users::uid_to_name(Uid::from_raw(s.uid)),
        crate::users::gid_to_name(Gid::from_raw(s.gid)),
        if s.acl { " +acl" } else { "" }
    )
}

fn collect(root: &Path, recursive: bool) -> Result<BTreeMap<PathBuf, Snap>> {
    let mut out = BTreeMap::new();
    if recursive && root.is_dir() {
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            let rel = p.strip_prefix(root).unwrap_or(p).to_path_buf();
            if let Some(s) = snap(p) {
                out.insert(rel, s);
            }
        }
    } else if let Some(s) = snap(root) {
        out.insert(PathBuf::from(""), s);
    }
    Ok(out)
}

pub fn cmd_compare(a: &str, b: &str, recursive: bool) -> Result<()> {
    let ra = resolve_path(a)?;
    let rb = resolve_path(b)?;
    let ma = collect(&ra, recursive)?;
    let mb = collect(&rb, recursive)?;
    let mut diff = 0usize;
    let mut keys: Vec<&PathBuf> = ma.keys().chain(mb.keys()).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        match (ma.get(k), mb.get(k)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) => {
                diff += 1;
                println!("~ {}", k.display());
                println!("    A: {}", fmt_snap(x));
                println!("    B: {}", fmt_snap(y));
            }
            (Some(x), None) => {
                diff += 1;
                println!("- {}  (only in A: {})", k.display(), fmt_snap(x));
            }
            (None, Some(y)) => {
                diff += 1;
                println!("+ {}  (only in B: {})", k.display(), fmt_snap(y));
            }
            (None, None) => {}
        }
    }
    if diff == 0 {
        println!("identical");
        Ok(())
    } else {
        Err(PmError::Other(format!("{diff} difference(s) found")))
    }
}
