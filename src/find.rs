//! `find`: permission-aware counterpart to coreutils `find`.
//!
//! Pipe-pure stdout: path-per-line (or NUL-separated). No colors, no
//! header, no summary on stdout — ever. On a TTY with no special flag
//! a small `#` banner is permitted (grep-friendly), and a spinner
//! may appear on stderr for long scans.

use std::io::Write;
use std::time::Instant;

use crate::audit::{scan, AuditFilter};
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::matcher::ExcludeSet;
use crate::render::{self, paint, Style};

#[allow(clippy::too_many_arguments)]
pub fn cmd_find(
    path: &str,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    print0: bool,
    count: bool,
    head: Option<usize>,
) -> Result<()> {
    let root = resolve_path(path)?;

    let stderr_tty = is_terminal::is_terminal(std::io::stderr());
    let spinner = if stderr_tty && !count {
        Some(render::spinner(&format!("scanning {}", root.display())))
    } else {
        None
    };
    let t0 = Instant::now();
    let hits = scan(&root, filter, exclude);
    let elapsed_ms = t0.elapsed().as_millis();
    if let Some(sp) = spinner {
        render::finish_progress(&sp, &format!("scanned in {elapsed_ms} ms"));
    }

    if count {
        println!("{}", hits.len());
        return Ok(());
    }

    let sep: u8 = if print0 { 0 } else { b'\n' };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let limit = head.unwrap_or(usize::MAX);
    let mut shown = 0usize;
    for h in &hits {
        if shown >= limit {
            break;
        }
        let _ = out.write_all(h.path.as_bytes());
        let _ = out.write_all(&[sep]);
        shown += 1;
    }

    // Optional stderr footer in TTY — never on stdout, never polluting pipes.
    if stderr_tty {
        let total = hits.len();
        let note = if let Some(n) = head {
            if total > n {
                format!("{shown}/{total} shown (--head {n})")
            } else {
                format!("{total} matches")
            }
        } else {
            format!("{total} matches")
        };
        eprintln!("  {}", paint(Style::Label, &format!("({note})")));
    }

    Ok(())
}
