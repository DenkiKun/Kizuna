use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use mdns_sd::{IfKind, Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

/// Tipo de serviço anunciado por todos os dispositivos Kizuna (ver docs/PROTOCOL.md).
pub const SERVICE_TYPE: &str = "_kizuna._tcp.local.";

/// Versão do protocolo anunciada no registo TXT (`v`).
const PROTOCOL_VERSION: &str = "0";

const TXT_NAME: &str = "name";
const TXT_VERSION: &str = "v";

/// Este dispositivo, tal como é anunciado na rede.
#[derive(Debug, Clone)]
pub struct LocalDevice {
    /// ID do dispositivo (derivado do certificado); é o nome da instância mDNS.
    pub id: String,
    /// Nome legível, mostrado ao utilizador.
    pub name: String,
    /// Porta TCP do servidor TLS.
    pub port: u16,
}

/// Um dispositivo Kizuna encontrado na rede local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDevice {
    pub id: String,
    pub name: String,
    pub addresses: Vec<Ipv4Addr>,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    Found(RemoteDevice),
    Lost { id: String },
}

/// Anúncio e procura de dispositivos por mDNS.
pub struct Discovery {
    daemon: ServiceDaemon,
    local: LocalDevice,
    fullname: String,
}

impl Discovery {
    /// Começa a anunciar `local` na rede local.
    pub fn start(local: LocalDevice) -> Result<Self> {
        let daemon = ServiceDaemon::new().context("falha a iniciar o serviço mDNS")?;
        // O servidor TLS só escuta em IPv4; não anunciar endereços IPv6.
        daemon.disable_interface(IfKind::IPv6)?;

        let info = service_info(&local)?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .context("falha a anunciar o serviço mDNS")?;
        Ok(Self {
            daemon,
            local,
            fullname,
        })
    }

    /// Procura outros dispositivos Kizuna (o próprio é ignorado).
    pub fn browse(&self) -> Result<Browser> {
        let events = self
            .daemon
            .browse(SERVICE_TYPE)
            .context("falha a procurar dispositivos")?;
        Ok(Browser {
            events,
            own_id: self.local.id.clone(),
        })
    }

    /// Retira o anúncio (avisando os outros dispositivos) e para o serviço mDNS.
    pub async fn shutdown(self) {
        const GOODBYE_TIMEOUT: Duration = Duration::from_secs(1);
        if let Ok(status) = self.daemon.unregister(&self.fullname) {
            let _ = tokio::time::timeout(GOODBYE_TIMEOUT, status.recv_async()).await;
        }
        if let Ok(status) = self.daemon.shutdown() {
            let _ = tokio::time::timeout(GOODBYE_TIMEOUT, status.recv_async()).await;
        }
    }
}

pub struct Browser {
    events: Receiver<ServiceEvent>,
    own_id: String,
}

impl Browser {
    /// Próximo evento de descoberta; `None` quando o serviço mDNS para.
    pub async fn next(&mut self) -> Option<DiscoveryEvent> {
        loop {
            let event = self.events.recv_async().await.ok()?;
            let Some(event) = translate(event) else {
                continue;
            };
            let id = match &event {
                DiscoveryEvent::Found(device) => &device.id,
                DiscoveryEvent::Lost { id } => id,
            };
            if *id != self.own_id {
                return Some(event);
            }
        }
    }
}

fn service_info(local: &LocalDevice) -> Result<ServiceInfo> {
    let host = format!("kizuna-{}.local.", local.id);
    let properties = [
        (TXT_NAME, local.name.as_str()),
        (TXT_VERSION, PROTOCOL_VERSION),
    ];
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &local.id,
        &host,
        (),
        local.port,
        &properties[..],
    )
    .context("anúncio mDNS inválido")?
    .enable_addr_auto();
    Ok(info)
}

fn translate(event: ServiceEvent) -> Option<DiscoveryEvent> {
    match event {
        ServiceEvent::ServiceResolved(info) => parse_resolved(&info).map(DiscoveryEvent::Found),
        ServiceEvent::ServiceRemoved(ty, fullname) if ty == SERVICE_TYPE => {
            id_from_fullname(&fullname).map(|id| DiscoveryEvent::Lost { id })
        }
        _ => None,
    }
}

/// Converte um serviço resolvido num dispositivo, descartando anúncios inválidos
/// ou de versões do protocolo incompatíveis.
fn parse_resolved(info: &ResolvedService) -> Option<RemoteDevice> {
    if info.ty_domain != SERVICE_TYPE
        || info.get_property_val_str(TXT_VERSION) != Some(PROTOCOL_VERSION)
        || info.get_port() == 0
    {
        return None;
    }
    let id = id_from_fullname(info.get_fullname())?;
    let mut addresses: Vec<Ipv4Addr> = info.get_addresses_v4().into_iter().collect();
    if addresses.is_empty() {
        return None;
    }
    addresses.sort();
    let name = match info.get_property_val_str(TXT_NAME) {
        Some(name) if !name.trim().is_empty() => name.to_string(),
        _ => id.clone(),
    };
    Some(RemoteDevice {
        id,
        name,
        addresses,
        port: info.get_port(),
    })
}

/// Extrai o ID do nome completo da instância (`<id>._kizuna._tcp.local.`).
fn id_from_fullname(fullname: &str) -> Option<String> {
    let id = fullname.strip_suffix(SERVICE_TYPE)?.strip_suffix('.')?;
    let valid = id.len() == 32 && id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
    valid.then(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const ID_A: &str = "0123456789abcdef0123456789abcdef";

    fn local(id: &str, port: u16) -> LocalDevice {
        LocalDevice {
            id: id.into(),
            name: "PC de teste".into(),
            port,
        }
    }

    fn resolved(info: ServiceInfo, ip: Ipv4Addr) -> ResolvedService {
        let mut resolved = info.as_resolved_service();
        resolved.addresses.insert(IpAddr::V4(ip).into());
        resolved
    }

    #[test]
    fn anuncio_tem_tipo_nome_e_txt_corretos() {
        let info = service_info(&local(ID_A, 4321)).unwrap();
        assert_eq!(info.get_fullname(), format!("{ID_A}.{SERVICE_TYPE}"));
        assert_eq!(info.get_port(), 4321);
        assert_eq!(info.get_property_val_str("name"), Some("PC de teste"));
        assert_eq!(info.get_property_val_str("v"), Some("0"));
        assert!(info.is_addr_auto());
    }

    #[test]
    fn anuncio_valido_e_convertido_em_dispositivo() {
        let info = service_info(&local(ID_A, 4321)).unwrap();
        let device = parse_resolved(&resolved(info, Ipv4Addr::new(192, 168, 1, 20))).unwrap();
        assert_eq!(
            device,
            RemoteDevice {
                id: ID_A.into(),
                name: "PC de teste".into(),
                addresses: vec![Ipv4Addr::new(192, 168, 1, 20)],
                port: 4321,
            }
        );
    }

    #[test]
    fn versao_incompativel_e_ignorada() {
        let props = [("name", "x"), ("v", "9")];
        let info = ServiceInfo::new(SERVICE_TYPE, ID_A, "h.local.", (), 1, &props[..]).unwrap();
        assert_eq!(parse_resolved(&resolved(info, Ipv4Addr::LOCALHOST)), None);
    }

    #[test]
    fn anuncio_sem_enderecos_e_ignorado() {
        let info = service_info(&local(ID_A, 4321)).unwrap();
        assert_eq!(parse_resolved(&info.as_resolved_service()), None);
    }

    #[test]
    fn nome_vazio_usa_o_id() {
        let mut device = local(ID_A, 1);
        device.name = "  ".into();
        let info = service_info(&device).unwrap();
        let parsed = parse_resolved(&resolved(info, Ipv4Addr::LOCALHOST)).unwrap();
        assert_eq!(parsed.name, ID_A);
    }

    #[test]
    fn id_extraido_do_nome_completo() {
        assert_eq!(
            id_from_fullname(&format!("{ID_A}.{SERVICE_TYPE}")).as_deref(),
            Some(ID_A)
        );
        assert_eq!(id_from_fullname("telemovel._kizuna._tcp.local."), None);
        assert_eq!(
            id_from_fullname(&format!("{ID_A}._outro._tcp.local.")),
            None
        );
        let upper = ID_A.to_uppercase();
        assert_eq!(id_from_fullname(&format!("{upper}.{SERVICE_TYPE}")), None);
    }

    #[test]
    fn remocao_de_outro_tipo_de_servico_e_ignorada() {
        let event = ServiceEvent::ServiceRemoved(
            "_http._tcp.local.".into(),
            format!("{ID_A}._http._tcp.local."),
        );
        assert_eq!(translate(event), None);
    }

    /// Anuncia e procura de verdade, através da interface de loopback.
    #[tokio::test]
    async fn dois_dispositivos_encontram_se_e_ignoram_se_a_si_proprios() {
        const ID_PC: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
        const ID_TELEMOVEL: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2";
        const TIMEOUT: Duration = Duration::from_secs(15);

        let pc = Discovery::start(local(ID_PC, 47001)).unwrap();
        let telemovel = Discovery::start(LocalDevice {
            id: ID_TELEMOVEL.into(),
            name: "Telemóvel".into(),
            port: 47002,
        })
        .unwrap();

        let mut browser = pc.browse().unwrap();
        let found = tokio::time::timeout(TIMEOUT, async {
            loop {
                match browser.next().await.expect("mDNS parou") {
                    DiscoveryEvent::Found(d) if d.id == ID_TELEMOVEL => return d,
                    DiscoveryEvent::Found(d) => {
                        assert_ne!(d.id, ID_PC, "encontrou-se a si próprio")
                    }
                    DiscoveryEvent::Lost { .. } => {}
                }
            }
        })
        .await
        .expect("o telemóvel não foi encontrado");

        assert_eq!(found.name, "Telemóvel");
        assert_eq!(found.port, 47002);
        assert!(!found.addresses.is_empty());

        telemovel.shutdown().await;
        tokio::time::timeout(TIMEOUT, async {
            loop {
                if let DiscoveryEvent::Lost { id } = browser.next().await.expect("mDNS parou") {
                    if id == ID_TELEMOVEL {
                        return;
                    }
                }
            }
        })
        .await
        .expect("a saída do telemóvel não foi detetada");

        pc.shutdown().await;
    }
}
