use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use mdns_sd::{IfKind, Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::protocol::clean_device_name;

/// Service type announced by every Kizuna device (see docs/PROTOCOL.md).
pub const SERVICE_TYPE: &str = "_kizuna._tcp.local.";

/// Protocol version announced in the TXT record (`v`).
const PROTOCOL_VERSION: &str = "0";

const TXT_NAME: &str = "name";
const TXT_VERSION: &str = "v";

/// This device, as announced on the network.
#[derive(Debug, Clone)]
pub struct LocalDevice {
    /// Device ID (derived from the certificate); it is the mDNS instance name.
    pub id: String,
    /// Human-readable name, shown to the user.
    pub name: String,
    /// TCP port of the TLS server.
    pub port: u16,
}

/// A Kizuna device found on the local network.
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

/// Announces and looks for devices over mDNS.
pub struct Discovery {
    daemon: ServiceDaemon,
    local: LocalDevice,
    fullname: String,
}

impl Discovery {
    /// Starts announcing `local` on the local network.
    pub fn start(local: LocalDevice) -> Result<Self> {
        let daemon = ServiceDaemon::new().context("failed to start the mDNS service")?;
        // The TLS server only listens on IPv4; don't announce IPv6 addresses.
        daemon.disable_interface(IfKind::IPv6)?;

        let info = service_info(&local)?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .context("failed to announce the mDNS service")?;
        Ok(Self {
            daemon,
            local,
            fullname,
        })
    }

    /// Looks for other Kizuna devices (this device itself is ignored).
    pub fn browse(&self) -> Result<Browser> {
        let events = self
            .daemon
            .browse(SERVICE_TYPE)
            .context("failed to look for devices")?;
        Ok(Browser {
            events,
            own_id: self.local.id.clone(),
        })
    }

    /// Withdraws the announcement (notifying the other devices) and stops the
    /// mDNS service.
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
    /// Next discovery event; `None` when the mDNS service stops.
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
    .context("invalid mDNS announcement")?
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

/// Turns a resolved service into a device, discarding invalid announcements
/// and incompatible protocol versions.
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
        Some(name) if !name.trim().is_empty() => clean_device_name(name),
        _ => id.clone(),
    };
    Some(RemoteDevice {
        id,
        name,
        addresses,
        port: info.get_port(),
    })
}

/// Extracts the ID from the full instance name (`<id>._kizuna._tcp.local.`).
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
            name: "Test PC".into(),
            port,
        }
    }

    fn resolved(info: ServiceInfo, ip: Ipv4Addr) -> ResolvedService {
        let mut resolved = info.as_resolved_service();
        resolved.addresses.insert(IpAddr::V4(ip).into());
        resolved
    }

    #[test]
    fn announcement_has_correct_type_name_and_txt() {
        let info = service_info(&local(ID_A, 4321)).unwrap();
        assert_eq!(info.get_fullname(), format!("{ID_A}.{SERVICE_TYPE}"));
        assert_eq!(info.get_port(), 4321);
        assert_eq!(info.get_property_val_str("name"), Some("Test PC"));
        assert_eq!(info.get_property_val_str("v"), Some("0"));
        assert!(info.is_addr_auto());
    }

    #[test]
    fn valid_announcement_becomes_a_device() {
        let info = service_info(&local(ID_A, 4321)).unwrap();
        let device = parse_resolved(&resolved(info, Ipv4Addr::new(192, 168, 1, 20))).unwrap();
        assert_eq!(
            device,
            RemoteDevice {
                id: ID_A.into(),
                name: "Test PC".into(),
                addresses: vec![Ipv4Addr::new(192, 168, 1, 20)],
                port: 4321,
            }
        );
    }

    #[test]
    fn incompatible_version_is_ignored() {
        let props = [("name", "x"), ("v", "9")];
        let info = ServiceInfo::new(SERVICE_TYPE, ID_A, "h.local.", (), 1, &props[..]).unwrap();
        assert_eq!(parse_resolved(&resolved(info, Ipv4Addr::LOCALHOST)), None);
    }

    #[test]
    fn announcement_without_addresses_is_ignored() {
        let info = service_info(&local(ID_A, 4321)).unwrap();
        assert_eq!(parse_resolved(&info.as_resolved_service()), None);
    }

    #[test]
    fn empty_name_falls_back_to_the_id() {
        let mut device = local(ID_A, 1);
        device.name = "  ".into();
        let info = service_info(&device).unwrap();
        let parsed = parse_resolved(&resolved(info, Ipv4Addr::LOCALHOST)).unwrap();
        assert_eq!(parsed.name, ID_A);
    }

    #[test]
    fn id_extracted_from_fullname() {
        assert_eq!(
            id_from_fullname(&format!("{ID_A}.{SERVICE_TYPE}")).as_deref(),
            Some(ID_A)
        );
        assert_eq!(id_from_fullname("phone._kizuna._tcp.local."), None);
        assert_eq!(
            id_from_fullname(&format!("{ID_A}._other._tcp.local.")),
            None
        );
        let upper = ID_A.to_uppercase();
        assert_eq!(id_from_fullname(&format!("{upper}.{SERVICE_TYPE}")), None);
    }

    #[test]
    fn removal_of_other_service_type_is_ignored() {
        let event = ServiceEvent::ServiceRemoved(
            "_http._tcp.local.".into(),
            format!("{ID_A}._http._tcp.local."),
        );
        assert_eq!(translate(event), None);
    }

    /// Really announces and browses, through the loopback interface.
    #[tokio::test]
    async fn two_devices_find_each_other_and_ignore_themselves() {
        const ID_PC: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
        const ID_PHONE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2";
        const TIMEOUT: Duration = Duration::from_secs(15);

        let pc = Discovery::start(local(ID_PC, 47001)).unwrap();
        let phone = Discovery::start(LocalDevice {
            id: ID_PHONE.into(),
            name: "Phone".into(),
            port: 47002,
        })
        .unwrap();

        let mut browser = pc.browse().unwrap();
        let found = tokio::time::timeout(TIMEOUT, async {
            loop {
                match browser.next().await.expect("mDNS stopped") {
                    DiscoveryEvent::Found(d) if d.id == ID_PHONE => return d,
                    DiscoveryEvent::Found(d) => {
                        assert_ne!(d.id, ID_PC, "found itself")
                    }
                    DiscoveryEvent::Lost { .. } => {}
                }
            }
        })
        .await
        .expect("the phone was not found");

        assert_eq!(found.name, "Phone");
        assert_eq!(found.port, 47002);
        assert!(!found.addresses.is_empty());

        phone.shutdown().await;
        tokio::time::timeout(TIMEOUT, async {
            loop {
                if let DiscoveryEvent::Lost { id } = browser.next().await.expect("mDNS stopped") {
                    if id == ID_PHONE {
                        return;
                    }
                }
            }
        })
        .await
        .expect("the phone leaving was not detected");

        pc.shutdown().await;
    }
}
