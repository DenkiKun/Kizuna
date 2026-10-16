//! The PC side of Kizuna: identity, discovery, TLS server and pairing. It
//! reports what happens through [`Event`]s and asks for pairing confirmations
//! through a [`Confirm`] callback, so the same service runs behind the
//! terminal (`kizuna-desktop daemon`) and behind the window.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncBufRead, AsyncWrite, BufReader};
use tokio::sync::Semaphore;

use crate::broadcast;
use crate::discovery::{Discovery, DiscoveryEvent, LocalDevice, RemoteDevice};
use crate::identity::{Fingerprint, Identity};
use crate::notify::{Notifier, Posted};
use crate::pairing::{self, Keys, Outcome, Prompt};
use crate::protocol::{escape_untrusted, read_message, write_message, Message};
use crate::tls;
use crate::trust::{TrustStore, TrustedDevice};

/// TCP port of the TLS server. Fixed, so it can be opened in the firewall.
pub const DEFAULT_PORT: u16 = 47820;

/// Time an unpaired device has to request pairing.
const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// A paired device that sends nothing (not even `ping`) for this long is
/// considered gone. Phones ping every 30 s.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Something that happened, for the user interface to show.
#[derive(Debug, Clone)]
pub enum Event {
    Started {
        device_name: String,
        device_id: String,
        fingerprint: Fingerprint,
        port: u16,
    },
    Found(RemoteDevice),
    Lost {
        id: String,
    },
    Connected {
        name: String,
        fingerprint: Fingerprint,
        peer: SocketAddr,
    },
    Disconnected {
        name: String,
        fingerprint: Fingerprint,
    },
    Received {
        name: String,
        kind: &'static str,
    },
    /// The phone forwarded a notification; it was shown on the desktop.
    Notification {
        name: String,
        app: String,
        title: String,
    },
    DesktopNotificationFailed(String),
    Paired {
        name: String,
    },
    PairingRejected,
    PairingRejectedByPeer,
    /// Already escaped: it may quote data from the other side.
    ConnectionError {
        peer: SocketAddr,
        error: String,
    },
    AcceptError(String),
    ResponderStopped(String),
    Stopping,
}

pub type EventSink = Arc<dyn Fn(Event) + Send + Sync>;

/// Asks the user to confirm a pairing (by typing the code shown on the other
/// device). Dropping the future cancels the question.
pub type Confirm = Arc<dyn Fn(Prompt) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

/// State shared by the service's connections.
struct Shared {
    fingerprint: Fingerprint,
    device_name: String,
    trust: TrustStore,
    events: EventSink,
    confirm: Confirm,
    /// Only one pairing at a time (avoids queues of bogus requests).
    pairing_slot: Semaphore,
    notifier: Arc<Notifier>,
}

/// Runs until `shutdown` completes, then withdraws the mDNS announcement.
pub async fn run(
    dir: &Path,
    events: EventSink,
    confirm: Confirm,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let device_name = device_name();
    let identity = Identity::load_or_create(dir, &device_name)?;

    let server = tls::Server::bind(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT)),
        &identity,
    )
    .await?;
    let port = server.local_addr()?.port();

    let local = LocalDevice {
        id: identity.device_id(),
        name: device_name.clone(),
        port,
    };
    // For networks without multicast (e.g. phone hotspots), also answer UDP probes.
    let responder = broadcast::Responder::bind(broadcast::bind_addr(), &local).await?;
    let discovery = Discovery::start(local)?;
    let mut browser = discovery.browse()?;

    events(Event::Started {
        device_name: device_name.clone(),
        device_id: identity.device_id(),
        fingerprint: identity.fingerprint(),
        port,
    });

    let sink = events.clone();
    tokio::spawn(async move {
        if let Err(e) = responder.run().await {
            sink(Event::ResponderStopped(format!("{e:#}")));
        }
    });
    let sink = events.clone();
    tokio::spawn(async move {
        while let Some(event) = browser.next().await {
            sink(match event {
                DiscoveryEvent::Found(device) => Event::Found(device),
                DiscoveryEvent::Lost { id } => Event::Lost { id },
            });
        }
    });

    let shared = Arc::new(Shared {
        fingerprint: identity.fingerprint(),
        device_name,
        trust: TrustStore::open(dir),
        events: events.clone(),
        confirm,
        pairing_slot: Semaphore::new(1),
        notifier: Arc::new(Notifier::new()),
    });

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            incoming = server.accept() => match incoming {
                Ok(incoming) => {
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let peer = incoming.peer();
                        let result = match incoming.handshake().await {
                            Ok(conn) => handle_connection(conn, peer, &shared).await,
                            Err(e) => Err(e),
                        };
                        if let Err(e) = result {
                            // Second line of defence: the error may quote data from the other side.
                            let error = escape_untrusted(&format!("{e:#}"));
                            (shared.events)(Event::ConnectionError { peer, error });
                        }
                    });
                }
                Err(e) => events(Event::AcceptError(format!("{e:#}"))),
            },
            _ = &mut shutdown => break,
        }
    }

    events(Event::Stopping);
    discovery.shutdown().await;
    Ok(())
}

async fn handle_connection(conn: tls::Connection, peer: SocketAddr, shared: &Shared) -> Result<()> {
    let fingerprint = conn.peer_fingerprint;
    let (reader, mut writer) = tokio::io::split(conn.stream);
    let mut reader = BufReader::new(reader);

    if let Some(device) = shared.trust.get(&fingerprint)? {
        (shared.events)(Event::Connected {
            name: device.name.clone(),
            fingerprint,
            peer,
        });
        return session(&mut reader, &mut writer, &device.name, fingerprint, shared).await;
    }

    // An unknown device may only request pairing.
    let first = tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, read_message(&mut reader))
        .await
        .map_err(|_| anyhow!("unpaired device did not request pairing"))??;
    let peer_name = match first {
        Some(Message::PairRequest { device_name }) => device_name,
        Some(other) => bail!("unpaired device sent {}; connection closed", other.kind()),
        None => return Ok(()),
    };

    let Ok(_slot) = shared.pairing_slot.try_acquire() else {
        write_message(&mut writer, &Message::PairReject).await?;
        bail!("pairing request rejected: another one is in progress");
    };
    let keys = Keys {
        own: shared.fingerprint,
        peer: fingerprint,
    };
    let confirm = shared.confirm.clone();
    let outcome = pairing::respond(
        &mut reader,
        &mut writer,
        keys,
        &shared.device_name,
        peer_name,
        move |prompt| confirm(prompt),
    )
    .await?;

    match outcome {
        Outcome::Paired { peer_name } => {
            shared
                .trust
                .add(TrustedDevice::new(fingerprint, peer_name.clone()))?;
            (shared.events)(Event::Paired {
                name: peer_name.clone(),
            });
            // The pairing connection carries on as the device's session.
            (shared.events)(Event::Connected {
                name: peer_name.clone(),
                fingerprint,
                peer,
            });
            session(&mut reader, &mut writer, &peer_name, fingerprint, shared).await
        }
        Outcome::RejectedLocally => {
            (shared.events)(Event::PairingRejected);
            Ok(())
        }
        Outcome::RejectedByPeer => {
            (shared.events)(Event::PairingRejectedByPeer);
            Ok(())
        }
    }
}

/// Connection with a paired device: answers `ping` and reports the other
/// messages (the features themselves come next). Ends when the device closes
/// the connection or stays silent for [`IDLE_TIMEOUT`].
async fn session<R, W>(
    reader: &mut R,
    writer: &mut W,
    name: &str,
    fingerprint: Fingerprint,
    shared: &Shared,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = async {
        loop {
            let message = tokio::time::timeout(IDLE_TIMEOUT, read_message(reader))
                .await
                .map_err(|_| anyhow!("no activity for {} s", IDLE_TIMEOUT.as_secs()))??;
            match message {
                None => return Ok(()),
                Some(Message::Ping) => write_message(writer, &Message::Pong).await?,
                Some(Message::Pong) => {}
                Some(Message::NotificationPosted {
                    id,
                    app,
                    title,
                    text,
                }) => {
                    let posted = Posted::cleaned(&id, &app, &title, &text);
                    (shared.events)(Event::Notification {
                        name: name.to_string(),
                        app: posted.app.clone(),
                        title: posted.title.clone(),
                    });
                    let notifier = shared.notifier.clone();
                    let events = shared.events.clone();
                    let device_name = name.to_string();
                    // The D-Bus call blocks; keep it off the async runtime.
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = notifier.post(fingerprint, &device_name, &posted) {
                            events(Event::DesktopNotificationFailed(format!("{e:#}")));
                        }
                    });
                }
                Some(Message::NotificationDismissed { id }) => {
                    let notifier = shared.notifier.clone();
                    let id = Posted::cleaned(&id, "", "", "").id;
                    tokio::task::spawn_blocking(move || notifier.dismiss(fingerprint, &id));
                }
                Some(message) => (shared.events)(Event::Received {
                    name: name.to_string(),
                    kind: message.kind(),
                }),
            }
        }
    }
    .await;
    (shared.events)(Event::Disconnected {
        name: name.to_string(),
        fingerprint,
    });
    result
}

/// Device name shown to others: the system hostname.
pub fn device_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Linux".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{duplex, split, AsyncWriteExt};

    fn shared(events: Arc<Mutex<Vec<Event>>>) -> Shared {
        let dir = tempfile::tempdir().unwrap();
        Shared {
            fingerprint: hex::encode([1; 32]).parse().unwrap(),
            device_name: "PC".into(),
            trust: TrustStore::open(dir.path()),
            events: Arc::new(move |e| events.lock().unwrap().push(e)),
            confirm: Arc::new(|_| Box::pin(async { false })),
            pairing_slot: Semaphore::new(1),
            notifier: Arc::new(Notifier::new()),
        }
    }

    fn phone() -> Fingerprint {
        hex::encode([2; 32]).parse().unwrap()
    }

    #[tokio::test]
    async fn answers_ping_and_reports_other_messages() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let shared = shared(events.clone());
        let (pc_side, phone_side) = duplex(4096);
        let (pc_read, mut pc_write) = split(pc_side);
        let (phone_read, mut phone_write) = split(phone_side);
        let mut pc_read = BufReader::new(pc_read);
        let mut phone_read = BufReader::new(phone_read);

        let pc = async { session(&mut pc_read, &mut pc_write, "Phone", phone(), &shared).await };
        let phone = async {
            write_message(&mut phone_write, &Message::Ping)
                .await
                .unwrap();
            let reply = read_message(&mut phone_read).await.unwrap();
            let text = Message::ClipboardUpdate { text: "x".into() };
            write_message(&mut phone_write, &text).await.unwrap();
            phone_write.shutdown().await.unwrap();
            reply
        };
        let (result, reply) = tokio::join!(pc, phone);
        result.unwrap();
        assert_eq!(reply, Some(Message::Pong));

        let events = events.lock().unwrap();
        assert!(matches!(
            &events[0],
            Event::Received {
                kind: "clipboard.update",
                ..
            }
        ));
        assert!(matches!(&events[1], Event::Disconnected { name, .. } if name == "Phone"));
        assert_eq!(events.len(), 2, "ping/pong must not be reported");
    }

    #[tokio::test(start_paused = true)]
    async fn silent_device_is_disconnected_after_the_idle_timeout() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let shared = shared(events.clone());
        let (pc_side, _phone_side) = duplex(4096);
        let (pc_read, mut pc_write) = split(pc_side);
        let mut pc_read = BufReader::new(pc_read);

        let started = tokio::time::Instant::now();
        let err = session(&mut pc_read, &mut pc_write, "Phone", phone(), &shared)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no activity"), "{err}");
        assert!(started.elapsed() >= IDLE_TIMEOUT);
        assert!(matches!(
            &events.lock().unwrap()[0],
            Event::Disconnected { .. }
        ));
    }
}
