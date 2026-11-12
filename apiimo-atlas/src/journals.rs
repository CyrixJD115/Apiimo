//! Durable journal primitives shared by every game-mutation record.
//!
//! Reference semantics (macOS `HomelandBuildPurchaseJournal`): private
//! directory (0700, owned by the current user), locked mutations (`flock`),
//! every mutation reloads from disk, atomic temp-file + rename + dir fsync,
//! bounded file size, never follows symlinks.

use crate::types::Failure;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Platform data dir for AniiStudio journals:
/// macOS `~/Library/Application Support/AniiStudio`, Linux `$XDG_DATA_HOME/AniiStudio`,
/// Windows `%APPDATA%\AniiStudio`.
pub fn atlas_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ANII_DATA_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "macos")]
    let base = std::env::var("HOME").map(PathBuf::from).map(|h| h.join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    #[cfg(windows)]
    let base = std::env::var("APPDATA").map(PathBuf::from);
    base.unwrap_or_else(|_| PathBuf::from(".")).join("AniiStudio")
}

/// RFC3339 UTC timestamp for journal records (no external time dependency in
/// the wire types themselves).
pub fn now_rfc3339() -> String {
    let d = time::OffsetDateTime::now_utc();
    // time's well-known RFC3339 format without extra deps on formatting style.
    let (year, month, day, hour, minute, second, millis) = (
        d.year(),
        u8::from(d.month()),
        d.day(),
        d.hour(),
        d.minute(),
        d.second(),
        d.millisecond(),
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Single-record locked JSON journal file (reference journal core).
pub struct LockedJournal {
    pub directory: PathBuf,
    pub file_name: &'static str,
}

impl LockedJournal {
    pub fn new(directory: PathBuf, file_name: &'static str) -> Result<Self, Failure> {
        let journal = Self { directory, file_name };
        journal.prepare_directory()?;
        Ok(journal)
    }

    fn prepare_directory(&self) -> Result<(), Failure> {
        let dir = &self.directory;
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(io_err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(io_err)?;
            }
            fsync_dir(dir).map_err(io_err)?;
        }
        let meta = std::fs::symlink_metadata(dir).map_err(|_| Failure::UncertainOutcome)?;
        if !meta.is_dir() {
            return Err(Failure::UncertainOutcome);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.uid() != current_uid() {
                return Err(Failure::UncertainOutcome);
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io_err)?;
        }
        Ok(())
    }

    fn path(&self) -> PathBuf {
        self.directory.join(self.file_name)
    }

    /// Run `body` under an exclusive lock, passing the freshly loaded record
    /// bytes (None when absent) and writing back what it returns.
    pub fn locked<T>(
        &self,
        body: impl FnOnce(Option<Vec<u8>>) -> Result<(Option<Vec<u8>>, T), Failure>,
    ) -> Result<T, Failure> {
        let lock_path = self.directory.join(format!("{}.lock", self.file_name));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            lock.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(io_err)?;
        }
        fs2::FileExt::lock_exclusive(&lock).map_err(io_err)?;
        let result = (|| {
            let current = self.load_unlocked()?;
            let (next, value) = body(current)?;
            if let Some(bytes) = &next {
                self.save_unlocked(bytes)?;
            }
            Ok(value)
        })();
        let _ = fs2::FileExt::unlock(&lock);
        result
    }

    /// Read without mutating (still under lock).
    pub fn read(&self) -> Result<Option<Vec<u8>>, Failure> {
        self.locked(|current| Ok::<_, Failure>((None, current)))
    }

    /// Like [`locked`], but the closure controls both the bytes to persist and
    /// the outcome, so a failure path can still durably record state (the
    /// reference journal saves `blocked` before rethrowing).
    pub fn locked_with_outcome<T>(
        &self,
        body: impl FnOnce(Option<Vec<u8>>) -> (Option<Vec<u8>>, Result<T, Failure>),
    ) -> Result<T, Failure> {
        let lock_path = self.directory.join(format!("{}.lock", self.file_name));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            lock.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(io_err)?;
        }
        fs2::FileExt::lock_exclusive(&lock).map_err(io_err)?;
        let outcome = (|| {
            let current = self.load_unlocked()?;
            let (bytes, outcome) = body(current);
            if let Some(bytes) = bytes {
                self.save_unlocked(&bytes)?;
            }
            outcome
        })();
        let _ = fs2::FileExt::unlock(&lock);
        outcome
    }

    fn load_unlocked(&self) -> Result<Option<Vec<u8>>, Failure> {
        let path = self.path();
        // Never follow a symlink into the journal.
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Failure::UncertainOutcome),
        };
        if !meta.is_file() || meta.len() > 131_072 {
            return Err(Failure::UncertainOutcome);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.uid() != current_uid() || meta.permissions().mode() & 0o777 != 0o600 {
                return Err(Failure::UncertainOutcome);
            }
        }
        std::fs::read(&path).map(Some).map_err(io_err)
    }

    fn save_unlocked(&self, bytes: &[u8]) -> Result<(), Failure> {
        let tmp = self.directory.join(format!(".pending-{}", uuid::Uuid::new_v4()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(io_err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(io_err)?;
            }
            file.write_all(bytes).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
        }
        std::fs::rename(&tmp, self.path()).map_err(io_err)?;
        fsync_dir(&self.directory).map_err(io_err)
    }
}

fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let file = std::fs::File::open(dir)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn io_err(e: std::io::Error) -> Failure {
    // I/O failure during a journalled mutation is never silently retried.
    let _ = e;
    Failure::UncertainOutcome
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_journal_round_trip_and_bounds() {
        let dir = std::env::temp_dir().join(format!("apiimo-atlas-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = LockedJournal::new(dir.clone(), "purchase.json").unwrap();
        let () = journal
            .locked(|current| {
                assert!(current.is_none());
                Ok::<_, Failure>((Some(b"{\"v\":1}".to_vec()), ()))
            })
            .unwrap();
        let bytes = journal.read().unwrap();
        assert_eq!(bytes, Some(b"{\"v\":1}".to_vec()));
        // A symlink standing in for the record is rejected, never followed.
        #[cfg(unix)]
        {
            let real = dir.join("real.json");
            std::fs::write(&real, b"{}").unwrap();
            let link = dir.join("purchase.json");
            std::fs::remove_file(&link).ok();
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(matches!(
                journal.locked(|c| Ok::<_, Failure>((c, ()))),
                Err(Failure::UncertainOutcome)
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
