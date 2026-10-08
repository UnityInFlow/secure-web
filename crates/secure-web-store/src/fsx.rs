//! Filesystem primitives for the corpus (ADR-015): plain bounded names, directories that are
//! never symbolic links, and atomic replace-by-rename within one directory.
//!
//! On Unix every store directory is held open as a [`Dir`] (a directory file descriptor opened
//! with `O_DIRECTORY | O_NOFOLLOW`), and everything below it is created, opened and renamed
//! *relative to that descriptor* (`mkdirat`, `openat(O_NOFOLLOW)`, `renameat`, `unlinkat`).
//! Pathnames are never re-resolved after a directory was opened, so swapping a directory (or any
//! of its ancestors) for a symbolic link cannot redirect a write: the write lands in the
//! directory the store created, or fails.
//!
//! A write goes to `.<name>.tmp`, created with `O_CREAT | O_EXCL | O_NOFOLLOW`, is fsynced, and
//! is renamed onto `<name>` in the same directory (`renameat` replaces a symlink at the
//! destination, it never writes through it). Making the rename durable is the caller's job
//! ([`Dir::sync`]); see `RunInner::write_run_files` for the order.
//!
//! Other platforms fall back to pathname checks immediately before each write (no protection
//! against a concurrent swap).

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::StoreError;

/// Longest file or directory name the store creates.
pub(crate) const MAX_NAME_LEN: usize = 96;

/// Permissions for agent-visible corpus files (subject to the process umask).
pub(crate) const MODE_PUBLIC_FILE: u32 = 0o644;
/// Permissions for agent-visible corpus directories.
pub(crate) const MODE_PUBLIC_DIR: u32 = 0o755;
/// Permissions for private-audit files: owner read/write only.
pub(crate) const MODE_PRIVATE_FILE: u32 = 0o600;
/// Permissions for private-audit directories: owner only.
pub(crate) const MODE_PRIVATE_DIR: u32 = 0o700;

/// Whether `name` is a single plain name the store may create: 1..=96 bytes of ASCII
/// `[a-z0-9._-]`, not starting with `.` (so never `.`, `..` or a hidden temp name).
pub(crate) fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn check_name(name: &str) -> Result<(), StoreError> {
    if is_safe_name(name) {
        Ok(())
    } else {
        Err(StoreError::UnsafePath)
    }
}

/// Fail unless `path` is a directory and not a symbolic link.
pub(crate) fn ensure_real_dir(path: &Path) -> Result<(), StoreError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|err| StoreError::io("inspect directory", &err))?;
    if meta.file_type().is_symlink() {
        return Err(StoreError::SymlinkRefused);
    }
    if !meta.is_dir() {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

/// Observes directory syncs (tests assert the durability order).
#[cfg(test)]
pub(crate) mod sync_log {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static LOG: RefCell<Option<Vec<PathBuf>>> = const { RefCell::new(None) };
    }

    /// Start recording directory syncs and file renames on this thread.
    pub(crate) fn start() {
        LOG.with(|log| *log.borrow_mut() = Some(Vec::new()));
    }

    /// Stop recording and return the events (`sync:<dir>` / `rename:<dir>/<name>`).
    pub(crate) fn take() -> Vec<PathBuf> {
        LOG.with(|log| log.borrow_mut().take().unwrap_or_default())
    }

    pub(crate) fn record(kind: &str, path: &Path) {
        LOG.with(|log| {
            if let Some(events) = log.borrow_mut().as_mut() {
                events.push(PathBuf::from(format!("{kind}:{}", path.display())));
            }
        });
    }
}

/// An open store directory. Children are resolved relative to it, never by pathname.
pub(crate) struct Dir {
    /// Canonical path at the time the directory was opened (reporting only).
    path: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

impl std::fmt::Debug for Dir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Dir").field(&self.path).finish()
    }
}

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::os::fd::{AsFd, OwnedFd};

    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;

    use super::*;

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    fn io_err(errno: Errno) -> io::Error {
        io::Error::from(errno)
    }

    fn mode(bits: u32) -> Mode {
        Mode::from_bits_truncate(bits as rustix::fs::RawMode)
    }

    /// Why `openat(dir, name, O_NOFOLLOW…)` failed: a symlink at `name` is `SymlinkRefused`,
    /// something that is not a directory is `UnsafePath`.
    fn classify(dir: &OwnedFd, name: &str, errno: Errno, op: &'static str) -> StoreError {
        match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
                StoreError::SymlinkRefused
            }
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::Directory => {
                StoreError::UnsafePath
            }
            _ => StoreError::io(op, &io_err(errno)),
        }
    }

    impl Dir {
        /// Open the directory at `path` (canonical; the final component must not be a
        /// symbolic link). Ancestors are resolved once, here.
        pub(crate) fn open(path: &Path) -> Result<Dir, StoreError> {
            let fd = rustix::fs::open(path, DIR_FLAGS, Mode::empty()).map_err(|errno| {
                // `ELOOP` or `ENOTDIR` depending on the platform: say which it was.
                match ensure_real_dir(path) {
                    Err(err) => err,
                    Ok(()) => StoreError::io("open directory", &io_err(errno)),
                }
            })?;
            Ok(Dir {
                path: path.to_path_buf(),
                fd,
            })
        }

        /// Create the directory `name` below this one with `mode` and open it (never following
        /// a symlink). With `allow_existing`, an existing real directory is accepted; otherwise
        /// an existing entry of any kind is [`StoreError::RunExists`].
        pub(crate) fn create_dir(
            &self,
            name: &str,
            mode_bits: u32,
            allow_existing: bool,
        ) -> Result<Dir, StoreError> {
            check_name(name)?;
            match rustix::fs::mkdirat(&self.fd, name, mode(mode_bits)) {
                Ok(()) => {}
                Err(Errno::EXIST) if allow_existing => {}
                Err(Errno::EXIST) => return Err(StoreError::RunExists),
                Err(errno) => return Err(StoreError::io("create directory", &io_err(errno))),
            }
            let fd = rustix::fs::openat(&self.fd, name, DIR_FLAGS, Mode::empty())
                .map_err(|errno| classify(&self.fd, name, errno, "open directory"))?;
            Ok(Dir {
                path: self.path.join(name),
                fd,
            })
        }

        /// Atomically write `bytes` to `name` in this directory (temp file, fsync, rename).
        pub(crate) fn write_atomic(
            &self,
            name: &str,
            bytes: &[u8],
            mode_bits: u32,
        ) -> Result<PathBuf, StoreError> {
            check_name(name)?;
            let tmp = format!(".{name}.tmp");
            let flags =
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let create = || rustix::fs::openat(&self.fd, tmp.as_str(), flags, mode(mode_bits));
            let fd = match create() {
                Ok(fd) => fd,
                Err(Errno::EXIST) => {
                    // A leftover temp entry (of any kind) from an interrupted write: unlink the
                    // entry itself (never its target) and retry once.
                    rustix::fs::unlinkat(&self.fd, tmp.as_str(), AtFlags::empty()).map_err(
                        |errno| StoreError::io("remove stale temp file", &io_err(errno)),
                    )?;
                    create().map_err(|errno| StoreError::io("create temp file", &io_err(errno)))?
                }
                Err(errno) => return Err(StoreError::io("create temp file", &io_err(errno))),
            };
            let mut file = File::from(fd);
            let written = file.write_all(bytes).and_then(|()| file.sync_all());
            drop(file);
            if let Err(err) = written {
                let _ = rustix::fs::unlinkat(&self.fd, tmp.as_str(), AtFlags::empty());
                return Err(StoreError::io("write temp file", &err));
            }
            if let Err(errno) = rustix::fs::renameat(&self.fd, tmp.as_str(), &self.fd, name) {
                let _ = rustix::fs::unlinkat(&self.fd, tmp.as_str(), AtFlags::empty());
                return Err(StoreError::io("rename temp file", &io_err(errno)));
            }
            let target = self.path.join(name);
            #[cfg(test)]
            sync_log::record("rename", &target);
            Ok(target)
        }

        /// fsync the directory so completed renames in it survive a crash.
        pub(crate) fn sync(&self) -> Result<(), StoreError> {
            rustix::fs::fsync(self.fd.as_fd())
                .map_err(|errno| StoreError::io("sync directory", &io_err(errno)))?;
            #[cfg(test)]
            sync_log::record("sync", &self.path);
            Ok(())
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::fs::{self, OpenOptions};

    use super::*;

    impl Dir {
        pub(crate) fn open(path: &Path) -> Result<Dir, StoreError> {
            ensure_real_dir(path)?;
            Ok(Dir {
                path: path.to_path_buf(),
            })
        }

        /// Pathname-based fallback: re-check the directory right before each use.
        fn check(&self) -> Result<(), StoreError> {
            ensure_real_dir(&self.path)?;
            let canonical =
                fs::canonicalize(&self.path).map_err(|err| StoreError::io("canonicalize", &err))?;
            if canonical != self.path {
                return Err(StoreError::UnsafePath);
            }
            Ok(())
        }

        pub(crate) fn create_dir(
            &self,
            name: &str,
            _mode_bits: u32,
            allow_existing: bool,
        ) -> Result<Dir, StoreError> {
            check_name(name)?;
            self.check()?;
            let path = self.path.join(name);
            match fs::create_dir(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists && allow_existing => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(StoreError::RunExists)
                }
                Err(err) => return Err(StoreError::io("create directory", &err)),
            }
            Dir::open(&path)
        }

        pub(crate) fn write_atomic(
            &self,
            name: &str,
            bytes: &[u8],
            _mode_bits: u32,
        ) -> Result<PathBuf, StoreError> {
            check_name(name)?;
            self.check()?;
            let tmp = self.path.join(format!(".{name}.tmp"));
            let target = self.path.join(name);
            let create = || OpenOptions::new().write(true).create_new(true).open(&tmp);
            let mut file = match create() {
                Ok(file) => file,
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&tmp)
                        .map_err(|err| StoreError::io("remove stale temp file", &err))?;
                    create().map_err(|err| StoreError::io("create temp file", &err))?
                }
                Err(err) => return Err(StoreError::io("create temp file", &err)),
            };
            let written = file.write_all(bytes).and_then(|()| file.sync_all());
            drop(file);
            if let Err(err) = written {
                let _ = fs::remove_file(&tmp);
                return Err(StoreError::io("write temp file", &err));
            }
            if let Err(err) = fs::rename(&tmp, &target) {
                let _ = fs::remove_file(&tmp);
                return Err(StoreError::io("rename temp file", &err));
            }
            Ok(target)
        }

        /// Directories cannot be opened for fsync here.
        pub(crate) fn sync(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }
}

impl Dir {
    /// The directory's canonical path when it was opened.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn root() -> (tempfile::TempDir, Dir) {
        let tmp = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(tmp.path()).unwrap();
        let dir = Dir::open(&path).unwrap();
        (tmp, dir)
    }

    #[test]
    fn safe_names() {
        for good in [
            "manifest.json",
            "000001-home.md",
            "doc_000001.raw",
            "open_0123456789ab",
        ] {
            assert!(is_safe_name(good), "{good}");
        }
        let long = "a".repeat(MAX_NAME_LEN + 1);
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "a/b",
            "a\\b",
            "A.md",
            "a\0b",
            "caf\u{e9}",
            "\u{202e}dm.exe",
            long.as_str(),
        ] {
            assert!(!is_safe_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let (_tmp, root) = root();
        let dir = root.create_dir("d", MODE_PUBLIC_DIR, false).unwrap();
        dir.write_atomic("f.json", b"one", MODE_PUBLIC_FILE)
            .unwrap();
        let path = dir
            .write_atomic("f.json", b"two", MODE_PUBLIC_FILE)
            .unwrap();
        assert_eq!(path, root.path().join("d/f.json"));
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["f.json"]);
        dir.sync().unwrap();
    }

    #[test]
    fn stale_temp_is_replaced() {
        let (_tmp, root) = root();
        fs::write(root.path().join(".f.json.tmp"), b"stale").unwrap();
        root.write_atomic("f.json", b"fresh", MODE_PUBLIC_FILE)
            .unwrap();
        assert_eq!(fs::read(root.path().join("f.json")).unwrap(), b"fresh");
        assert!(!root.path().join(".f.json.tmp").exists());
    }

    #[test]
    fn existing_dir_is_refused_unless_allowed() {
        let (_tmp, root) = root();
        root.create_dir("d", MODE_PUBLIC_DIR, false).unwrap();
        assert!(matches!(
            root.create_dir("d", MODE_PUBLIC_DIR, false),
            Err(StoreError::RunExists)
        ));
        root.create_dir("d", MODE_PUBLIC_DIR, true).unwrap();
        fs::write(root.path().join("file"), b"x").unwrap();
        assert!(matches!(
            root.create_dir("file", MODE_PUBLIC_DIR, true),
            Err(StoreError::UnsafePath)
        ));
        assert!(matches!(
            Dir::open(&root.path().join("file")),
            Err(StoreError::UnsafePath)
        ));
    }

    #[test]
    fn unsafe_names_are_refused_before_touching_disk() {
        let (_tmp, root) = root();
        assert!(matches!(
            root.write_atomic("../x", b"", MODE_PUBLIC_FILE),
            Err(StoreError::UnsafePath)
        ));
        assert!(matches!(
            root.create_dir("..", MODE_PUBLIC_DIR, true),
            Err(StoreError::UnsafePath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        let (_tmp, root) = root();
        let target = root.create_dir("target", MODE_PUBLIC_DIR, false).unwrap();
        std::os::unix::fs::symlink(target.path(), root.path().join("link")).unwrap();
        assert!(matches!(
            Dir::open(&root.path().join("link")),
            Err(StoreError::SymlinkRefused)
        ));
        assert!(matches!(
            root.create_dir("link", MODE_PUBLIC_DIR, true),
            Err(StoreError::SymlinkRefused)
        ));
        assert!(matches!(
            root.create_dir("link", MODE_PUBLIC_DIR, false),
            Err(StoreError::RunExists)
        ));
        // A symlink planted at the final name is replaced, not written through.
        let outside = root.path().join("outside.txt");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, target.path().join("f")).unwrap();
        target.write_atomic("f", b"new", MODE_PUBLIC_FILE).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        assert!(!fs::symlink_metadata(target.path().join("f"))
            .unwrap()
            .file_type()
            .is_symlink());
        // ... and so is one planted at the temp name.
        std::os::unix::fs::symlink(&outside, target.path().join(".g.tmp")).unwrap();
        target.write_atomic("g", b"new", MODE_PUBLIC_FILE).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
    }

    /// Once a directory is open, replacing it (or an ancestor) with a symlink does not redirect
    /// writes: they land in the directory the store created.
    #[cfg(unix)]
    #[test]
    fn swapped_directories_do_not_redirect_writes() {
        let (_tmp, root) = root();
        let outside = root.create_dir("outside", MODE_PUBLIC_DIR, false).unwrap();
        let run = root.create_dir("run", MODE_PUBLIC_DIR, false).unwrap();
        let pages = run.create_dir("pages", MODE_PUBLIC_DIR, false).unwrap();
        // Swap `run/pages` for a symlink to `outside`.
        fs::rename(pages.path(), root.path().join("run/moved")).unwrap();
        std::os::unix::fs::symlink(outside.path(), pages.path()).unwrap();
        pages
            .write_atomic("a.md", b"page", MODE_PUBLIC_FILE)
            .unwrap();
        // Swap the run directory (an ancestor) for a symlink too.
        fs::rename(run.path(), root.path().join("run-moved")).unwrap();
        std::os::unix::fs::symlink(outside.path(), run.path()).unwrap();
        pages
            .write_atomic("b.md", b"page", MODE_PUBLIC_FILE)
            .unwrap();
        run.write_atomic("manifest.json", b"{}", MODE_PUBLIC_FILE)
            .unwrap();
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
        let moved = root.path().join("run-moved");
        for file in ["moved/a.md", "moved/b.md", "manifest.json"] {
            assert!(moved.join(file).is_file(), "{file}");
        }
        // Creating a subdirectory through a swapped parent stays inside it as well.
        let sub = run.create_dir("metadata", MODE_PUBLIC_DIR, false).unwrap();
        sub.write_atomic("1.json", b"{}", MODE_PUBLIC_FILE).unwrap();
        assert!(moved.join("metadata/1.json").is_file());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn private_mode_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, root) = root();
        let dir = root.create_dir("p", MODE_PRIVATE_DIR, false).unwrap();
        let file = dir
            .write_atomic("x.raw", b"raw", MODE_PRIVATE_FILE)
            .unwrap();
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & !MODE_PRIVATE_FILE, 0, "{mode:o}");
        let dir_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode & !MODE_PRIVATE_DIR, 0, "{dir_mode:o}");
    }
}
