//! Advisory `flock` on the backup directory, serializing concurrent mutations.

use std::fs::OpenOptions;

use crate::config::ensure_backup_root;
use crate::errors::Result;

/// Execute `f` while holding an exclusive flock on the backup directory.
/// Prevents concurrent janitor instances from corrupting backups.
pub fn with_lock<T, F: FnOnce() -> Result<T>>(f: F) -> Result<T> {
    let root = ensure_backup_root()?;
    let lock_path = root.join(".janitor.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    // Blocking exclusive lock using libc directly (nix::fcntl::flock is deprecated).
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(crate::errors::PmError::Other(format!(
            "failed to acquire lock: {}",
            std::io::Error::last_os_error()
        )));
    }
    let result = f();
    // Lock is released when lock_file is dropped.
    drop(lock_file);
    result
}
