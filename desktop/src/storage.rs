use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Diretório de configuração do Kizuna: `$XDG_CONFIG_HOME/kizuna`
/// (dentro de um Flatpak, aponta para `~/.var/app/<id>/config`).
pub fn config_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        _ => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".config"),
            None => bail!("nem XDG_CONFIG_HOME nem HOME estão definidos"),
        },
    };
    Ok(base.join("kizuna"))
}

/// Escreve `contents` em `path` de forma atómica, legível só pelo utilizador.
/// Cria o diretório pai (modo 0700) se não existir.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().context("caminho sem diretório")?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("falha a criar {}", dir.display()))?;

    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("falha a criar {}", tmp.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("falha a gravar {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn ficheiro_e_diretorio_so_acessiveis_pelo_utilizador() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kizuna").join("segredo");
        write_private(&path, b"um").unwrap();
        write_private(&path, b"dois").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"dois");
        let file_mode = fs::metadata(&path).unwrap().permissions().mode();
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600);
        assert_eq!(dir_mode & 0o777, 0o700);
        assert!(!dir.path().join("kizuna").join("segredo.tmp").exists());
    }
}
