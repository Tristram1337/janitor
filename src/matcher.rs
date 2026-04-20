//! Glob-based include/exclude matching for mass operations.

use crate::errors::{PmError, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;

/// A compiled set of exclude globs. Empty = no exclusion.
#[derive(Debug, Clone, Default)]
pub struct ExcludeSet {
    set: Option<GlobSet>,
}

impl ExcludeSet {
    pub fn new(patterns: &[String]) -> Result<Self> {
        if patterns.is_empty() {
            return Ok(Self { set: None });
        }
        let mut b = GlobSetBuilder::new();
        for p in patterns {
            let g = Glob::new(p)
                .map_err(|e| PmError::Other(format!("invalid --exclude '{p}': {e}")))?;
            b.add(g);
        }
        let set = b
            .build()
            .map_err(|e| PmError::Other(format!("failed to build exclude set: {e}")))?;
        Ok(Self { set: Some(set) })
    }

    /// Returns true when `path` matches any exclude pattern.
    /// Matching is performed against the full path string AND the basename,
    /// which lets users write both `/etc/shadow` and `*.bak`.
    pub fn is_excluded(&self, path: &Path) -> bool {
        let Some(set) = &self.set else { return false };
        if set.is_match(path) {
            return true;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if set.is_match(name) {
                return true;
            }
        }
        false
    }
}
