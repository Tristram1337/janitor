//! `compare A B`: report differences in mode/owner/group/ACL.

use crate::acl::has_extended_acl;
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::render::{paint, summary_line, Style};
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
    let mut keys: Vec<&PathBuf> = ma.keys().chain(mb.keys()).collect();
    keys.sort();
    keys.dedup();

    let mut changed = 0usize;
    let mut only_a = 0usize;
    let mut only_b = 0usize;

    println!();
    println!(
        "  {}  {}  {}  {}",
        paint(Style::Primary, &ra.display().to_string()),
        paint(Style::Separator, "↔"),
        paint(Style::Primary, &rb.display().to_string()),
        paint(Style::Label, if recursive { "(recursive)" } else { "" })
    );
    println!();

    for k in keys {
        let disp = if k.as_os_str().is_empty() {
            ".".to_string()
        } else {
            k.display().to_string()
        };
        match (ma.get(k), mb.get(k)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) => {
                changed += 1;
                println!(
                    "  {}  {}",
                    paint(Style::WarnMajor, "~"),
                    paint(Style::Primary, &disp)
                );
                println!("      A: {}", paint(Style::Label, &fmt_snap(x)));
                println!("      B: {}", paint(Style::Label, &fmt_snap(y)));
            }
            (Some(x), None) => {
                only_a += 1;
                println!(
                    "  {}  {}  {}",
                    paint(Style::Deny, "-"),
                    paint(Style::Primary, &disp),
                    paint(Style::Label, &format!("(only in A: {})", fmt_snap(x)))
                );
            }
            (None, Some(y)) => {
                only_b += 1;
                println!(
                    "  {}  {}  {}",
                    paint(Style::Ok, "+"),
                    paint(Style::Primary, &disp),
                    paint(Style::Label, &format!("(only in B: {})", fmt_snap(y)))
                );
            }
            (None, None) => {}
        }
    }

    println!();
    if changed == 0 && only_a == 0 && only_b == 0 {
        println!("  {}", paint(Style::Ok, "identical"));
        return Ok(());
    }
    let changed_s = changed.to_string();
    let only_a_s = only_a.to_string();
    let only_b_s = only_b.to_string();
    let segs: Vec<(&str, &str)> = vec![
        (changed_s.as_str(), "changed"),
        (only_a_s.as_str(), "only-in-A"),
        (only_b_s.as_str(), "only-in-B"),
    ];
    eprintln!("{}", summary_line(&segs));
    Ok(())
}
