//! `prune-backups`: delete old snapshots, keeping the newest N.

use std::fs;
use std::path::PathBuf;

use crate::config::ensure_backup_root;
use crate::errors::Result;
use crate::locking::with_lock;

/// Prune old backups, keeping only the `keep` most recent.
/// Returns the number pruned.
pub fn prune_backups(keep: usize, dry_run: bool) -> Result<usize> {
    with_lock(|| {
        let root = ensure_backup_root()?;
        let mut files: Vec<PathBuf> = fs::read_dir(&root)?
            .filter_map(|e| {
                let e = e.ok()?;
                let p = e.path();
                let ext = p.extension().and_then(|e| e.to_str())?;
                if ext == "mpk" || ext == "json" {
                    Some(p)
                } else {
                    None
                }
            })
            .collect();
        files.sort();

        if files.len() <= keep {
            println!("{} backup(s), keeping all.", files.len());
            return Ok(0);
        }

        let to_delete = if keep == 0 {
            &files[..]
        } else {
            &files[..files.len() - keep]
        };

        let count = to_delete.len();
        for f in to_delete {
            if dry_run {
                println!("[dry-run] rm {}", f.display());
            } else {
                fs::remove_file(f)?;
            }
        }
        println!("pruned {count} backup(s), kept {keep}.");
        Ok(count)
    })
}
