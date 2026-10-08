//! Resolving `server.workspace` / `--workspace` (`~` expansion).

use std::path::{Component, Path, PathBuf};

use crate::error::StoreError;

/// The current user's home directory (`HOME`, else `USERPROFILE`), if set and non-empty.
pub fn home_dir() -> Option<PathBuf> {
    ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(std::env::var_os)
        .find(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Expand a leading `~` component to `home`. `~user` forms are refused (not supported), as is a
/// `~` path when no home directory is known. Other paths are returned unchanged.
pub fn expand_home(path: &Path, home: Option<&Path>) -> Result<PathBuf, StoreError> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(first)) if first == "~" => {
            let home = home.ok_or(StoreError::Workspace(
                "`~` used but no home directory is set",
            ))?;
            Ok(home.join(components.as_path()))
        }
        Some(Component::Normal(first)) if first.to_string_lossy().starts_with('~') => Err(
            StoreError::Workspace("`~user` paths are not supported; use an absolute path"),
        ),
        _ => Ok(path.to_path_buf()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_to_home() {
        let home = Path::new("/home/me");
        assert_eq!(
            expand_home(Path::new("~/.secure-web"), Some(home)).unwrap(),
            Path::new("/home/me/.secure-web")
        );
        assert_eq!(expand_home(Path::new("~"), Some(home)).unwrap(), home);
        assert_eq!(
            expand_home(Path::new("/srv/sw"), Some(home)).unwrap(),
            Path::new("/srv/sw")
        );
        assert_eq!(
            expand_home(Path::new("rel/~"), Some(home)).unwrap(),
            Path::new("rel/~")
        );
    }

    #[test]
    fn unsupported_tilde_forms_are_errors() {
        assert!(expand_home(Path::new("~other/x"), Some(Path::new("/h"))).is_err());
        assert!(expand_home(Path::new("~/x"), None).is_err());
    }
}
