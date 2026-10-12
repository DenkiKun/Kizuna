use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::storage;

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
        storage::write_private(&path, pem.as_bytes())?;
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

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.cert)
    }

    /// ID estável do dispositivo, derivado do certificado.
    pub fn device_id(&self) -> String {
        self.fingerprint().device_id()
    }
}

/// Impressão digital SHA-256 de um certificado (DER). Mostrada e guardada em
/// hexadecimal minúsculo.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(cert: &CertificateDer<'_>) -> Self {
        Self(Sha256::digest(cert.as_ref()).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn device_id(&self) -> String {
        self.to_string()[..DEVICE_ID_LEN].to_string()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

impl FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 64 || s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(anyhow!("impressão digital inválida: {s:?}"));
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(s, &mut bytes)
            .map_err(|_| anyhow!("impressão digital inválida: {s:?}"))?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

        let fp = identity.fingerprint().to_string();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(identity.device_id(), fp[..DEVICE_ID_LEN]);
        assert_eq!(fp.parse::<Fingerprint>().unwrap(), identity.fingerprint());
    }

    #[test]
    fn impressao_digital_invalida_e_recusada() {
        let ok = "ab".repeat(32);
        assert!(ok.parse::<Fingerprint>().is_ok());
        assert!(ok.to_uppercase().parse::<Fingerprint>().is_err());
        assert!(ok[..62].parse::<Fingerprint>().is_err());
        assert!("zz".repeat(32).parse::<Fingerprint>().is_err());
    }

    #[test]
    fn ficheiro_corrompido_da_erro_em_vez_de_nova_identidade() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(IDENTITY_FILE), "lixo").unwrap();
        assert!(Identity::load_or_create(dir.path(), "pc").is_err());
    }
}
