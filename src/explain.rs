//! `explain PATH [-U USER]`: why does USER have (or not have) their
//! current effective access?
//!
//! Layout (variant A): ancestor chain top-down, `✗` on the first step
//! that blocks traversal, `→` on the target when the chain succeeds, a
//! single-line verdict, and a `try:` footer with copy-pasteable fix
//! suggestions. See designs/03-explain.md.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid};

use crate::access::effective_for_user_path;
use crate::acl::has_extended_acl;
use crate::errors::{PmError, Result};
use crate::helpers::resolve_path;
use crate::render::{self, glyphs, paint, Style};
use crate::users::{gid_to_name, lookup_user, uid_to_name, user_gids};

fn current_username() -> Result<String> {
    let uid = nix::unistd::getuid();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .ok_or_else(|| PmError::Other(format!("cannot resolve current uid {}", uid.as_raw())))
}

/// Walk from `/` down to (and including) `target`.
fn ancestry(target: &Path) -> Vec<PathBuf> {
    let mut segs = Vec::new();
    let mut cur = target.to_path_buf();
    segs.push(cur.clone());
    while let Some(parent) = cur.parent() {
        if parent == cur {
            break;
        }
        segs.push(parent.to_path_buf());
        cur = parent.to_path_buf();
    }
    segs.reverse();
    if !segs.first().map(|p| p == Path::new("/")).unwrap_or(false) {
        segs.insert(0, PathBuf::from("/"));
    }
    segs.dedup();
    segs
}

pub fn cmd_explain(path: &str, for_user: Option<&str>) -> Result<()> {
    let target = resolve_path(path)?;
    let username = match for_user {
        Some(u) => u.to_string(),
        None => current_username()?,
    };
    // Validate user early for nice error.
    let u = lookup_user(&username)?;
    let user_gids_set: HashSet<u32> = user_gids(&username)?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    let uid = u.uid.as_raw();

    println!();
    println!(
        "{} {}  ({} {})",
        paint(Style::Separator, glyphs().header_marker),
        paint(Style::Primary, &target.display().to_string()),
        paint(Style::Label, "as user"),
        paint(Style::User, &username)
    );
    println!("  {}", render::rule(61));

    let chain = ancestry(&target);

    // First walk: find blocker (first ancestor dir without traverse).
    let mut blocker_idx: Option<usize> = None;
    for (i, p) in chain.iter().enumerate() {
        if *p == target {
            continue;
        }
        let d = effective_for_user_path(p, &username).ok();
        if !d.as_ref().map(|dd| dd.exec).unwrap_or(false) {
            blocker_idx = Some(i);
            break;
        }
    }

    // Column widths.
    let max_path_w = chain
        .iter()
        .map(|p| p.display().to_string().chars().count())
        .max()
        .unwrap_or(10)
        .max(20);
    let path_w = max_path_w.min(55);

    // Render each step.
    for (i, p) in chain.iter().enumerate() {
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) => {
                println!(
                    "  {}  {:<path_w$}  {}",
                    paint(Style::Danger, glyphs().cross),
                    p.display().to_string(),
                    paint(Style::Danger, &format!("<{e}>")),
                    path_w = path_w
                );
                continue;
            }
        };
        let mode = md.mode() & 0o7777;
        let sym = render::mode_symbolic_colored(mode, md.is_dir(), md.file_type().is_symlink());
        let oct = paint(Style::Primary, &format!("{mode:04o}"));
        let owner = format!(
            "{}{}{}",
            paint(Style::User, &uid_to_name(Uid::from_raw(md.uid()))),
            paint(Style::Separator, ":"),
            paint(Style::Group, &gid_to_name(Gid::from_raw(md.gid())))
        );
        let acl_hint = if has_extended_acl(p) {
            format!(" {}", paint(Style::AclMarker, "+acl"))
        } else {
            String::new()
        };

        let is_target = *p == target;
        let marker = if Some(i) == blocker_idx {
            paint(Style::Danger, glyphs().cross)
        } else if is_target && blocker_idx.is_none() {
            paint(Style::Ok, glyphs().arrow_right)
        } else {
            " ".to_string()
        };

        let rhs = if is_target {
            // Target: read/write/exec verdict phrasing.
            let d = effective_for_user_path(p, &username).unwrap_or_else(|_| {
                crate::access::AccessDecision {
                    read: false,
                    write: false,
                    exec: false,
                    reason: "error".into(),
                }
            });
            let bits = format!(
                "r={} w={} x={}",
                ynb(d.read),
                ynb(d.write),
                ynb(d.exec)
            );
            let verdict_style = if blocker_idx.is_some() {
                Style::Deny
            } else if d.read {
                Style::Ok
            } else {
                Style::Deny
            };
            format!("{}   {}", paint(verdict_style, &bits), paint(Style::Label, &format!("via {}", d.reason)))
        } else {
            // Ancestor: traverse verdict.
            let d = effective_for_user_path(p, &username).unwrap_or_else(|_| {
                crate::access::AccessDecision {
                    read: false,
                    write: false,
                    exec: false,
                    reason: "error".into(),
                }
            });
            if d.exec {
                format!(
                    "{}   {}",
                    paint(Style::Ok, "traverse ok"),
                    paint(Style::Label, &format!("via {}", d.reason))
                )
            } else {
                let mut s = format!(
                    "{}   {}",
                    paint(Style::Danger, "no traverse"),
                    paint(Style::Label, &format!("via {}", d.reason))
                );
                if Some(i) == blocker_idx {
                    s.push_str("  ");
                    s.push_str(&paint(Style::Danger, "← blocks here"));
                }
                s
            }
        };

        let path_disp = p.display().to_string();
        let path_visual = format!("{}{}", path_disp, acl_hint);
        // Left-align path column with manual padding over visible width.
        let pad = path_w.saturating_sub(path_disp.chars().count());
        println!(
            "  {}  {}{}  {}  {}  {}",
            marker,
            path_visual,
            " ".repeat(pad.max(1)),
            oct,
            format!("{}  {}", sym, owner),
            rhs
        );
    }

    // ── Verdict ───────────────────────────────────────────────────────
    println!();
    let target_d = effective_for_user_path(&target, &username).unwrap_or_else(|_| {
        crate::access::AccessDecision {
            read: false,
            write: false,
            exec: false,
            reason: "error".into(),
        }
    });
    let traversable = blocker_idx.is_none();
    let (r, w, x) = if traversable {
        (target_d.read, target_d.write, target_d.exec)
    } else {
        (false, false, false)
    };
    println!(
        "  {} {}: read = {} {} write = {} {} exec = {}",
        paint(Style::Label, "verdict for"),
        paint(Style::User, &username),
        yn_col(r),
        paint(Style::Separator, glyphs().midot),
        yn_col(w),
        paint(Style::Separator, glyphs().midot),
        yn_col(x)
    );

    // Reason line.
    let reason_text = if let Some(i) = blocker_idx {
        let p = &chain[i];
        format!(
            "traverse denied at {} ({} not in group evaluated by ACL/POSIX)",
            p.display(),
            username
        )
    } else if r || w || x {
        target_d.reason.clone()
    } else {
        format!("{} (target denies all access)", target_d.reason)
    };
    println!(
        "  {} {}",
        paint(Style::Label, "reason:"),
        paint(Style::Primary, &reason_text)
    );

    // Try-hints.
    let (hints, hint_title) = suggest_fixes(&target, &username, blocker_idx.map(|i| &chain[i]), &target_d, traversable);
    if !hints.is_empty() {
        println!();
        println!("  {}", paint(Style::Label, hint_title));
        for h in &hints {
            println!("    {}", paint(Style::Traverse, h));
        }
    }

    let _ = (uid, user_gids_set); // already validated
    println!();
    Ok(())
}

fn ynb(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn yn_col(b: bool) -> String {
    if b {
        paint(Style::Ok, "yes")
    } else {
        paint(Style::Deny, "no")
    }
}

fn suggest_fixes(
    target: &Path,
    username: &str,
    blocker: Option<&PathBuf>,
    target_d: &crate::access::AccessDecision,
    traversable: bool,
) -> (Vec<String>, &'static str) {
    let mut hints = Vec::new();
    if let Some(b) = blocker {
        hints.push(format!("janitor grant {username} rx {}", b.display()));
        if !target_d.read {
            hints.push(format!("janitor grant {username} r  {}", target.display()));
        }
    } else if traversable && !target_d.read {
        hints.push(format!("janitor grant {username} r {}", target.display()));
    }
    (hints, "try:")
}
