use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Kizuna's configuration directory: `$XDG_CONFIG_HOME/kizuna`
/// (inside a Flatpak, this points to `~/.var/app/<id>/config`).
pub fn config_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        _ => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".config"),
            None => bail!("neither XDG_CONFIG_HOME nor HOME is set"),
        },
    };
    Ok(base.join("kizuna"))
}

/// Atomically writes `contents` to `path`, readable only by the user.
/// Creates the parent directory (mode 0700) if it does not exist.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no directory")?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;

    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("failed to create {}", tmp.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("failed to save {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn file_and_directory_only_accessible_by_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kizuna").join("secret");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"two");
        let file_mode = fs::metadata(&path).unwrap().permissions().mode();
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600);
        assert_eq!(dir_mode & 0o777, 0o700);
        assert!(!dir.path().join("kizuna").join("secret.tmp").exists());
    }
}
