use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::storage;

/// File holding the private key and the certificate, in PEM.
const IDENTITY_FILE: &str = "identity.pem";

/// Number of hexadecimal characters of the fingerprint used as the device ID
/// (128 bits). Fits in a DNS label (max. 63 bytes).
const DEVICE_ID_LEN: usize = 32;

/// Self-signed certificate and private key that identify this device.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    /// Loads the identity stored in `dir`, or generates a new one on first run.
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
            .with_context(|| format!("failed to read the certificate from {}", path.display()))?
            .ok_or_else(|| anyhow!("{} does not contain a certificate", path.display()))?;
        let key = PrivateKeyDer::from_pem_file(path)
            .with_context(|| format!("failed to read the private key from {}", path.display()))?;
        Ok(Self { cert, key })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.cert)
    }

    /// Stable device ID, derived from the certificate.
    pub fn device_id(&self) -> String {
        self.fingerprint().device_id()
    }
}

/// SHA-256 fingerprint of a certificate (DER). Shown and stored as lowercase
/// hexadecimal.
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
            return Err(anyhow!("invalid fingerprint: {s:?}"));
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| anyhow!("invalid fingerprint: {s:?}"))?;
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

/// Generates an ECDSA P-256 key and a self-signed certificate, in PEM.
fn generate_pem(device_name: &str) -> Result<String> {
    let key_pair = KeyPair::generate().context("failed to generate the key pair")?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, device_name);
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate the certificate")?;
    Ok(format!("{}{}", key_pair.serialize_pem(), cert.pem()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn generated_on_first_run_and_reused_afterwards() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kizuna");

        let first = Identity::load_or_create(&config, "test-pc").unwrap();
        let second = Identity::load_or_create(&config, "other-name").unwrap();

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.key.secret_der(), second.key.secret_der());
    }

    #[test]
    fn different_identity_per_installation() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ia = Identity::load_or_create(a.path(), "pc").unwrap();
        let ib = Identity::load_or_create(b.path(), "pc").unwrap();
        assert_ne!(ia.fingerprint(), ib.fingerprint());
    }

    #[test]
    fn fingerprint_and_id_format() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_create(dir.path(), "pc").unwrap();

        let fp = identity.fingerprint().to_string();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(identity.device_id(), fp[..DEVICE_ID_LEN]);
        assert_eq!(fp.parse::<Fingerprint>().unwrap(), identity.fingerprint());
    }

    #[test]
    fn invalid_fingerprint_is_rejected() {
        let ok = "ab".repeat(32);
        assert!(ok.parse::<Fingerprint>().is_ok());
        assert!(ok.to_uppercase().parse::<Fingerprint>().is_err());
        assert!(ok[..62].parse::<Fingerprint>().is_err());
        assert!("zz".repeat(32).parse::<Fingerprint>().is_err());
    }

    #[test]
    fn corrupted_file_is_an_error_instead_of_a_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(IDENTITY_FILE), "garbage").unwrap();
        assert!(Identity::load_or_create(dir.path(), "pc").is_err());
    }
}
