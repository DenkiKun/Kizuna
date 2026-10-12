use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity::Fingerprint;
use crate::storage;

const TRUST_FILE: &str = "trusted.json";

/// Um dispositivo emparelhado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub fingerprint: Fingerprint,
    pub name: String,
    /// Segundos desde 1970-01-01 UTC.
    pub paired_at: u64,
}

impl TrustedDevice {
    pub fn new(fingerprint: Fingerprint, name: String) -> Self {
        let paired_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            fingerprint,
            name,
            paired_at,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct TrustFile {
    devices: Vec<TrustedDevice>,
}

/// Lista de dispositivos emparelhados, em `trusted.json`. É relida do disco
/// em cada consulta, para ver alterações feitas por outros processos (ex.:
/// `kizuna-desktop unpair` com o daemon a correr).
pub struct TrustStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl TrustStore {
    pub fn open(dir: &Path) -> Self {
        Self {
            path: dir.join(TRUST_FILE),
            write_lock: Mutex::new(()),
        }
    }

    pub fn list(&self) -> Result<Vec<TrustedDevice>> {
        Ok(self.read()?.devices)
    }

    pub fn get(&self, fingerprint: &Fingerprint) -> Result<Option<TrustedDevice>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|d| d.fingerprint == *fingerprint))
    }

    /// Acrescenta (ou atualiza) um dispositivo.
    pub fn add(&self, device: TrustedDevice) -> Result<()> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.read()?;
        file.devices.retain(|d| d.fingerprint != device.fingerprint);
        file.devices.push(device);
        self.write(&file)
    }

    /// Esquece os dispositivos cujo ID começa por `id_prefix`. Devolve os removidos.
    pub fn remove(&self, id_prefix: &str) -> Result<Vec<TrustedDevice>> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.read()?;
        let (removed, kept) = file.devices.into_iter().partition(|d| {
            !id_prefix.is_empty() && d.fingerprint.to_string().starts_with(id_prefix)
        });
        file.devices = kept;
        if !removed.is_empty() {
            self.write(&file)?;
        }
        Ok(removed)
    }

    fn read(&self) -> Result<TrustFile> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("{} está corrompido", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustFile::default()),
            Err(e) => Err(e).with_context(|| format!("falha a ler {}", self.path.display())),
        }
    }

    fn write(&self, file: &TrustFile) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(file)?;
        json.push(b'\n');
        storage::write_private(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> Fingerprint {
        hex::encode([byte; 32]).parse().unwrap()
    }

    #[test]
    fn sem_ficheiro_nao_ha_dispositivos() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(dir.path());
        assert!(store.list().unwrap().is_empty());
        assert_eq!(store.get(&fp(1)).unwrap(), None);
    }

    #[test]
    fn dispositivo_adicionado_persiste() {
        let dir = tempfile::tempdir().unwrap();
        let device = TrustedDevice::new(fp(1), "Pixel".into());
        TrustStore::open(dir.path()).add(device.clone()).unwrap();

        let reopened = TrustStore::open(dir.path());
        assert_eq!(reopened.get(&fp(1)).unwrap(), Some(device));
        assert_eq!(reopened.get(&fp(2)).unwrap(), None);
    }

    #[test]
    fn reemparelhar_substitui_a_entrada() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(dir.path());
        store
            .add(TrustedDevice::new(fp(1), "Antigo".into()))
            .unwrap();
        store.add(TrustedDevice::new(fp(1), "Novo".into())).unwrap();
        let devices = store.list().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Novo");
    }

    #[test]
    fn remover_por_prefixo_do_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(dir.path());
        store.add(TrustedDevice::new(fp(0x11), "A".into())).unwrap();
        store.add(TrustedDevice::new(fp(0x22), "B".into())).unwrap();

        assert!(store.remove("").unwrap().is_empty());
        assert!(store.remove("33").unwrap().is_empty());
        let removed = store.remove("1111").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "A");
        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(store.get(&fp(0x22)).unwrap().unwrap().name, "B");
    }

    #[test]
    fn ficheiro_corrompido_da_erro() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(TRUST_FILE), "{").unwrap();
        assert!(TrustStore::open(dir.path()).get(&fp(1)).is_err());
    }
}
