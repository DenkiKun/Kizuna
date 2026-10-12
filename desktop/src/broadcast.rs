//! Discovery by UDP broadcast, for networks that block multicast (mDNS), such
//! as phone hotspots. A client broadcasts `discovery.probe`; the PC replies
//! with `discovery.announce` straight to the sender (see docs/PROTOCOL.md).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::net::UdpSocket;

use crate::discovery::LocalDevice;

/// UDP port for probes (same number as the TLS server's TCP port).
pub const DISCOVERY_PORT: u16 = 47820;

/// Larger datagrams are ignored.
const MAX_DATAGRAM: usize = 1024;

/// Minimum time between two replies to the same address.
const REPLY_INTERVAL: Duration = Duration::from_secs(1);

const PROTOCOL_VERSION: &str = "0";

/// Answers discovery probes from the local network.
pub struct Responder {
    socket: UdpSocket,
    reply: Vec<u8>,
    last_reply: HashMap<IpAddr, Instant>,
}

impl Responder {
    pub async fn bind(addr: SocketAddr, local: &LocalDevice) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to listen for discovery probes on {addr}"))?;
        Ok(Self {
            socket,
            reply: announcement(local),
            last_reply: HashMap::new(),
        })
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Answers probes until the socket fails.
    pub async fn run(mut self) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM + 1];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            if len > MAX_DATAGRAM || !is_probe(&buf[..len]) || !self.should_reply(from.ip()) {
                continue;
            }
            // Errors sending one reply (e.g. the sender went away) are not fatal.
            let _ = self.socket.send_to(&self.reply, from).await;
        }
    }

    /// Only local senders, and at most one reply per address per interval, so
    /// the daemon cannot be used to flood a third party with replies.
    fn should_reply(&mut self, ip: IpAddr) -> bool {
        if !is_local(ip) {
            return false;
        }
        let now = Instant::now();
        self.last_reply
            .retain(|_, at| now.duration_since(*at) < REPLY_INTERVAL);
        if self.last_reply.contains_key(&ip) {
            return false;
        }
        self.last_reply.insert(ip, now);
        true
    }
}

fn announcement(local: &LocalDevice) -> Vec<u8> {
    json!({
        "type": "discovery.announce",
        "body": {
            "v": PROTOCOL_VERSION,
            "id": local.id,
            "name": local.name,
            "port": local.port,
        },
    })
    .to_string()
    .into_bytes()
}

fn is_probe(datagram: &[u8]) -> bool {
    let Ok(message) = serde_json::from_slice::<Value>(datagram) else {
        return false;
    };
    message["type"] == "discovery.probe" && message["body"]["v"] == PROTOCOL_VERSION
}

/// Private, link-local and loopback IPv4 addresses.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        IpAddr::V6(_) => false,
    }
}

/// Address to bind the responder to.
pub fn bind_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE: &[u8] = br#"{"type":"discovery.probe","body":{"v":"0"}}"#;

    fn local() -> LocalDevice {
        LocalDevice {
            id: "0123456789abcdef0123456789abcdef".into(),
            name: "Test PC".into(),
            port: 47820,
        }
    }

    async fn responder() -> SocketAddr {
        let responder = Responder::bind("127.0.0.1:0".parse().unwrap(), &local())
            .await
            .unwrap();
        let addr = responder.local_addr().unwrap();
        tokio::spawn(responder.run());
        addr
    }

    async fn ask(to: SocketAddr, datagram: &[u8]) -> Option<Value> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(datagram, to).await.unwrap();
        let mut buf = [0; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap();
        Some(serde_json::from_slice(&buf[..len]).unwrap())
    }

    #[tokio::test]
    async fn probe_gets_an_announcement() {
        let addr = responder().await;
        let reply = ask(addr, PROBE).await.expect("no reply");
        assert_eq!(reply["type"], "discovery.announce");
        assert_eq!(reply["body"]["v"], "0");
        assert_eq!(reply["body"]["id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(reply["body"]["name"], "Test PC");
        assert_eq!(reply["body"]["port"], 47820);
    }

    #[tokio::test]
    async fn anything_else_is_ignored() {
        let addr = responder().await;
        for datagram in [
            &b"hello"[..],
            br#"{"type":"discovery.probe","body":{"v":"9"}}"#,
            br#"{"type":"pair.request","body":{"device_name":"x"}}"#,
            &[b' '; MAX_DATAGRAM + 1][..],
        ] {
            assert_eq!(ask(addr, datagram).await, None);
        }
    }

    #[tokio::test]
    async fn replies_to_the_same_address_are_rate_limited() {
        let addr = responder().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..5 {
            client.send_to(PROBE, addr).await.unwrap();
        }
        let mut buf = [0; 2048];
        let mut replies = 0;
        while tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buf))
            .await
            .is_ok()
        {
            replies += 1;
        }
        assert_eq!(replies, 1);
    }

    #[test]
    fn only_local_addresses_get_replies() {
        for ip in [
            "10.74.139.121",
            "192.168.1.2",
            "172.16.0.9",
            "169.254.1.1",
            "127.0.0.1",
        ] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "100.64.0.1", "::1"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }
}
