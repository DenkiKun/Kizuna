use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

/// Ficheiro com a chave privada e o certificado, em PEM.
const IDENTITY_FILE: &str = "identity.pem";

/// Número de caracteres hexadecimais da impressão digital usados como ID do
/// dispositivo (128 bits). Cabe numa etiqueta DNS (máx. 63 bytes).
const DEVICE_ID_LEN: usize = 32;

/// Certificado autoassinado e chave privada que identificam este dispositivo.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    /// Carrega a identidade guardada em `dir`, ou gera uma nova na primeira execução.
    pub fn load_or_create(dir: &Path, device_name: &str) -> Result<Self> {
        let path = dir.join(IDENTITY_FILE);
        if path.exists() {
            return Self::load(&path);
        }
        let pem = generate_pem(device_name)?;
        save(dir, &path, &pem)?;
        Self::load(&path)
    }

    fn load(path: &Path) -> Result<Self> {
        let cert = CertificateDer::pem_file_iter(path)
            .and_then(|mut certs| certs.next().transpose())
            .with_context(|| format!("falha a ler o certificado de {}", path.display()))?
            .ok_or_else(|| anyhow!("{} não contém um certificado", path.display()))?;
        let key = PrivateKeyDer::from_pem_file(path)
            .with_context(|| format!("falha a ler a chave privada de {}", path.display()))?;
        Ok(Self { cert, key })
    }

    /// Impressão digital SHA-256 do certificado, em hexadecimal.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.cert)
    }

    /// ID estável do dispositivo, derivado do certificado.
    pub fn device_id(&self) -> String {
        self.fingerprint()[..DEVICE_ID_LEN].to_string()
    }
}

/// Impressão digital SHA-256 de um certificado, em hexadecimal minúsculo.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Diretório onde a identidade é guardada: `$XDG_CONFIG_HOME/kizuna`
/// (dentro de um Flatpak, aponta para `~/.var/app/<id>/config`).
pub fn default_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        _ => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".config"),
            None => bail!("nem XDG_CONFIG_HOME nem HOME estão definidos"),
        },
    };
    Ok(base.join("kizuna"))
}

/// Gera uma chave ECDSA P-256 e um certificado autoassinado, em PEM.
fn generate_pem(device_name: &str) -> Result<String> {
    let key_pair = KeyPair::generate().context("falha a gerar o par de chaves")?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, device_name);
    let cert = params
        .self_signed(&key_pair)
        .context("falha a gerar o certificado")?;
    Ok(format!("{}{}", key_pair.serialize_pem(), cert.pem()))
}

/// Escreve o ficheiro de forma atómica, legível só pelo utilizador.
fn save(dir: &Path, path: &Path, pem: &str) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("falha a criar {}", dir.display()))?;

    let tmp = path.with_extension("pem.tmp");
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("falha a criar {}", tmp.display()))?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("falha a gravar {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn gera_na_primeira_execucao_e_reutiliza_depois() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kizuna");

        let first = Identity::load_or_create(&config, "pc-teste").unwrap();
        let second = Identity::load_or_create(&config, "outro-nome").unwrap();

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.key.secret_der(), second.key.secret_der());
    }

    #[test]
    fn chave_so_legivel_pelo_utilizador() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kizuna");
        Identity::load_or_create(&config, "pc-teste").unwrap();

        let file_mode = fs::metadata(config.join(IDENTITY_FILE))
            .unwrap()
            .permissions()
            .mode();
        let dir_mode = fs::metadata(&config).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600);
        assert_eq!(dir_mode & 0o777, 0o700);
        assert!(!config.join("identity.pem.tmp").exists());
    }

    #[test]
    fn identidades_diferentes_por_instalacao() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ia = Identity::load_or_create(a.path(), "pc").unwrap();
        let ib = Identity::load_or_create(b.path(), "pc").unwrap();
        assert_ne!(ia.fingerprint(), ib.fingerprint());
    }

    #[test]
    fn formato_da_impressao_digital_e_do_id() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_create(dir.path(), "pc").unwrap();

        let fp = identity.fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(identity.device_id(), fp[..DEVICE_ID_LEN]);
    }

    #[test]
    fn ficheiro_corrompido_da_erro_em_vez_de_nova_identidade() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(IDENTITY_FILE), "lixo").unwrap();
        assert!(Identity::load_or_create(dir.path(), "pc").is_err());
    }
}
