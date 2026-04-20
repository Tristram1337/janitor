//! `tree`: colored permission tree with per-user access highlighting.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid};

use crate::acl::has_extended_acl;
use crate::cli::ColorMode;
use crate::errors::Result;
use crate::helpers::{path_chain, resolve_path};
use crate::users::{gid_to_name, lookup_user, uid_to_name, user_gids};

// ── Color palette ──────────────────────────────────────────────────────

struct Palette {
    reset: &'static str,
    dim: &'static str,
    acc: &'static str,  // green: user has access
    trav: &'static str, // cyan: traverse only
    deny: &'static str, // dim red: no access
    hl: &'static str,   // bold yellow: managed chain highlight
    dir: &'static str,  // bold blue: default directory
    link: &'static str, // magenta: symlinks
    sep: &'static str,
}

const PAL_ON: Palette = Palette {
    reset: "\x1b[0m",
    dim: "\x1b[2m",
    acc: "\x1b[32m",
    trav: "\x1b[36m",
    deny: "\x1b[2;31m",
    hl: "\x1b[1;33m",
    dir: "\x1b[1;34m",
    link: "\x1b[35m",
    sep: "\x1b[2m",
};

const PAL_OFF: Palette = Palette {
    reset: "",
    dim: "",
    acc: "",
    trav: "",
    deny: "",
    hl: "",
    dir: "",
    link: "",
    sep: "",
};

fn should_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            // auto: only if stdout is a terminal and TERM isn't dumb
            atty_check() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
        }
    }
}

fn atty_check() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

// ── User context for --for-user ────────────────────────────────────────

#[allow(dead_code)]
struct UserCtx {
    name: String,
    uid: u32,
    gids: HashSet<u32>,
}

fn build_user_ctx(username: &str) -> Result<UserCtx> {
    let u = lookup_user(username)?;
    let gids: HashSet<u32> = user_gids(username)?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    Ok(UserCtx {
        name: username.to_string(),
        uid: u.uid.as_raw(),
        gids,
    })
}

/// (read, write, execute) for a user context on a specific inode.
fn effective_local(md: &fs::Metadata, ctx: &UserCtx) -> (bool, bool, bool) {
    let mode = md.mode() & 0o7777;
    if ctx.uid == 0 {
        let is_dir = md.is_dir();
        return (true, true, is_dir || (mode & 0o111 != 0));
    }
    let triad = if ctx.uid == md.uid() {
        (mode >> 6) & 0o7
    } else if ctx.gids.contains(&md.gid()) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    (triad & 0o4 != 0, triad & 0o2 != 0, triad & 0o1 != 0)
}

// ── Counts ─────────────────────────────────────────────────────────────

struct Counts {
    dirs: usize,
    files: usize,
    denied: usize,
}

// ── Public entry point ─────────────────────────────────────────────────

pub fn cmd_tree(
    path: &str,
    max_depth: Option<usize>,
    show_parents: bool,
    highlight: Option<&str>,
    for_user: Option<&str>,
    color_mode: ColorMode,
    show_acl: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let use_color = should_color(color_mode);
    let pal = if use_color { &PAL_ON } else { &PAL_OFF };

    // Highlight set: all segments from / to the highlighted path.
    let highlight_set: HashSet<PathBuf> = match highlight {
        Some(h) => {
            let hp = resolve_path(h)?;
            path_chain(&hp, Path::new("/")).into_iter().collect()
        }
        None => HashSet::new(),
    };

    let user_ctx = match for_user {
        Some(u) => Some(build_user_ctx(u)?),
        None => None,
    };

    let mut counts = Counts {
        dirs: 0,
        files: 0,
        denied: 0,
    };

    // Show parents above root if requested.
    if show_parents {
        let parents = path_chain(&root, Path::new("/"));
        // All segments except the last (which is root itself).
        for p in &parents[..parents.len().saturating_sub(1)] {
            print_line(
                p,
                "",
                &p.display().to_string(),
                pal,
                &highlight_set,
                user_ctx.as_ref(),
                true,
                true,
                show_acl,
            );
        }
        if parents.len() > 1 {
            println!("{}{}{}", pal.sep, "─".repeat(60), pal.reset);
        }
    }

    walk_tree(
        &root,
        "",
        true,
        true,
        0,
        max_depth,
        pal,
        &highlight_set,
        user_ctx.as_ref(),
        true,
        &mut counts,
        show_acl,
    );

    println!();
    let dir_word = if counts.dirs == 1 {
        "directory"
    } else {
        "directories"
    };
    let file_word = if counts.files == 1 { "file" } else { "files" };
    print!("{} {dir_word}, {} {file_word}", counts.dirs, counts.files);
    if counts.denied > 0 {
        print!(", {} unreadable", counts.denied);
    }
    println!();

    if user_ctx.is_some() && use_color {
        println!();
        println!(
            "  {}■{} readable by {}   {}■{} traverse-only (can pass, can't list)   {}■{} no access",
            pal.acc,
            pal.reset,
            for_user.unwrap(),
            pal.trav,
            pal.reset,
            pal.deny,
            pal.reset,
        );
    }
    if !highlight_set.is_empty() && use_color {
        println!(
            "  {}■{} managed-chain highlight (grant path)",
            pal.hl, pal.reset,
        );
    }

    Ok(())
}

// ── Recursive walk ─────────────────────────────────────────────────────

fn walk_tree(
    path: &Path,
    prefix: &str,
    is_root: bool,
    is_last: bool,
    depth: usize,
    max_depth: Option<usize>,
    pal: &Palette,
    highlight_set: &HashSet<PathBuf>,
    user_ctx: Option<&UserCtx>,
    parent_reachable: bool,
    counts: &mut Counts,
    show_acl: bool,
) {
    let connector = if is_root {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };
    let name = if is_root {
        path.display().to_string()
    } else {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string())
    };

    let full_prefix = format!("{prefix}{connector}");
    let self_reachable = print_line(
        path,
        &full_prefix,
        &name,
        pal,
        highlight_set,
        user_ctx,
        parent_reachable,
        false,
        show_acl,
    );

    // Update counts.
    match fs::symlink_metadata(path) {
        Ok(md) => {
            if md.is_dir() && !md.file_type().is_symlink() {
                counts.dirs += 1;
            } else {
                counts.files += 1;
            }
        }
        Err(_) => {
            counts.denied += 1;
            return;
        }
    }

    // Recurse into dirs.
    if let Some(max) = max_depth {
        if depth >= max {
            return;
        }
    }

    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        return;
    }

    let children: Vec<PathBuf> = match fs::read_dir(path) {
        Ok(rd) => {
            let mut v: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
            v.sort();
            v
        }
        Err(_) => {
            let child_prefix = if is_last || is_root {
                format!("{prefix}    ")
            } else {
                format!("{prefix}│   ")
            };
            println!(
                "{}{}└── <permission denied>{}",
                child_prefix, pal.dim, pal.reset
            );
            counts.denied += 1;
            return;
        }
    };

    let child_prefix = if is_root {
        prefix.to_string()
    } else if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    for (i, child) in children.iter().enumerate() {
        walk_tree(
            child,
            &child_prefix,
            false,
            i == children.len() - 1,
            depth + 1,
            max_depth,
            pal,
            highlight_set,
            user_ctx,
            self_reachable,
            counts,
            show_acl,
        );
    }
}

// ── Single-line rendering ──────────────────────────────────────────────

/// Print one entry line. Returns whether this node is reachable for the
/// user context (so children can propagate reachability).
fn print_line(
    path: &Path,
    prefix: &str,
    name: &str,
    pal: &Palette,
    highlight_set: &HashSet<PathBuf>,
    user_ctx: Option<&UserCtx>,
    parent_reachable: bool,
    is_parent_view: bool,
    show_acl: bool,
) -> bool {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            println!("{prefix}{}{name}  <{e}>{}", pal.dim, pal.reset);
            return false;
        }
    };

    let mode_str = filemode(md.mode());
    let owner = uid_to_name(Uid::from_raw(md.uid()));
    let group = gid_to_name(Gid::from_raw(md.gid()));

    // Coloring logic.
    let mut color = "";
    let mut reachable = parent_reachable;

    if let Some(ctx) = user_ctx {
        let (r, _w, x) = effective_local(&md, ctx);
        let is_dir = md.is_dir() && !md.file_type().is_symlink();
        if !parent_reachable {
            color = pal.deny;
            reachable = false;
        } else if is_dir {
            if r && x {
                color = pal.acc;
                reachable = true;
            } else if x && !r {
                color = pal.trav;
                reachable = true;
            } else {
                color = pal.deny;
                reachable = false;
            }
        } else {
            // file
            color = if r { pal.acc } else { pal.deny };
        }
    } else if md.is_dir() && !md.file_type().is_symlink() {
        color = pal.dir;
    } else if md.file_type().is_symlink() {
        color = pal.link;
    }

    // Highlight marker.
    let marker = if !highlight_set.is_empty() {
        if highlight_set.contains(path) {
            format!("{}●{} ", pal.hl, pal.reset)
        } else {
            "  ".to_string()
        }
    } else {
        String::new()
    };

    let parent_prefix = if is_parent_view { "↑ " } else { "" };
    let acl_mark = if show_acl && has_extended_acl(path) {
        "+"
    } else {
        " "
    };

    println!(
        "{prefix}{marker}{parent_prefix}{}{mode_str}{acl_mark}{}  {owner}:{group}  {color}{name}{}",
        pal.dim, pal.reset, pal.reset,
    );

    reachable
}

/// Convert mode bits to a string like `drwxr-x---` (mimics Python's stat.filemode).
fn filemode(mode: u32) -> String {
    let file_type = match mode & 0o170000 {
        0o140000 => 's', // socket
        0o120000 => 'l', // symlink
        0o100000 => '-', // regular
        0o060000 => 'b', // block device
        0o040000 => 'd', // directory
        0o020000 => 'c', // char device
        0o010000 => 'p', // FIFO
        _ => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(file_type);
    // owner
    s.push(if mode & 0o400 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o200 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o4000 != 0 {
        if mode & 0o100 != 0 {
            's'
        } else {
            'S'
        }
    } else {
        if mode & 0o100 != 0 {
            'x'
        } else {
            '-'
        }
    });
    // group
    s.push(if mode & 0o040 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o020 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o2000 != 0 {
        if mode & 0o010 != 0 {
            's'
        } else {
            'S'
        }
    } else {
        if mode & 0o010 != 0 {
            'x'
        } else {
            '-'
        }
    });
    // other
    s.push(if mode & 0o004 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o002 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o1000 != 0 {
        if mode & 0o001 != 0 {
            't'
        } else {
            'T'
        }
    } else {
        if mode & 0o001 != 0 {
            'x'
        } else {
            '-'
        }
    });
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filemode() {
        // drwxr-x--- = 0o40750
        assert_eq!(filemode(0o40750), "drwxr-x---");
        // -rw-r----- = 0o100640
        assert_eq!(filemode(0o100640), "-rw-r-----");
        // -rwxrwxrwx = 0o100777
        assert_eq!(filemode(0o100777), "-rwxrwxrwx");
        // drwx--x--- = 0o40710
        assert_eq!(filemode(0o40710), "drwx--x---");
    }
}
