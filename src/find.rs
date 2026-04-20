//! `find`: permission-aware counterpart to coreutils `find`.
//!
//! Accepts the same filters as `audit` but prints only matching paths,
//! optionally NUL-separated so it can pipe into `janitor chmod --stdin0`.

use crate::audit::{scan, AuditFilter};
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::matcher::ExcludeSet;

#[allow(clippy::too_many_arguments)]
pub fn cmd_find(
    path: &str,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    print0: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let hits = scan(&root, filter, exclude);
    let sep: u8 = if print0 { 0 } else { b'\n' };
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for h in &hits {
        let _ = out.write_all(h.path.as_bytes());
        let _ = out.write_all(&[sep]);
    }
    Ok(())
}
