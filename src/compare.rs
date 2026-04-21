//! `compare A B`: report differences in mode/owner/group/ACL.

use crate::acl::has_extended_acl;
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::render::{paint, Style};
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

fn fmt_snap_kv(s: &Snap) -> String {
    let kind_word = match s.kind {
        'd' => "dir",
        'l' => "symlink",
        _ => "file",
    };
    format!(
        "{} {:04o}  {}:{}{}",
        kind_word,
        s.mode,
        crate::users::uid_to_name(Uid::from_raw(s.uid)),
        crate::users::gid_to_name(Gid::from_raw(s.gid)),
        if s.acl { "  +acl" } else { "" }
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
        "  {}  {}  {}  {}  {}",
        paint(Style::Label, "compare"),
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
                println!("      {}  {}", paint(Style::Label, "A:"), paint(Style::Label, &fmt_snap_kv(x)));
                println!("      {}  {}", paint(Style::Label, "B:"), paint(Style::Label, &fmt_snap_kv(y)));
            }
            (Some(x), None) => {
                only_a += 1;
                println!(
                    "  {}  {}",
                    paint(Style::Deny, "-"),
                    paint(Style::Primary, &disp)
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "A:"),
                    paint(Style::Label, &fmt_snap_kv(x))
                );
                println!("      {}  {}", paint(Style::Label, "B:"), paint(Style::Label, "(missing)"));
            }
            (None, Some(y)) => {
                only_b += 1;
                println!(
                    "  {}  {}",
                    paint(Style::Ok, "+"),
                    paint(Style::Primary, &disp)
                );
                println!("      {}  {}", paint(Style::Label, "A:"), paint(Style::Label, "(missing)"));
                println!(
                    "      {}  {}",
                    paint(Style::Label, "B:"),
                    paint(Style::Label, &fmt_snap_kv(y))
                );
            }
            (None, None) => {}
        }
    }

    println!();
    if changed == 0 && only_a == 0 && only_b == 0 {
        println!("  {}  {}", paint(Style::Ok, "✓"), paint(Style::Primary, "identical"));
        println!();
        return Ok(());
    }
    eprintln!(
        "{}  {} changed · {} only in A · {} only in B",
        paint(Style::Label, "summary:"),
        changed,
        only_a,
        only_b
    );
    Ok(())
}
