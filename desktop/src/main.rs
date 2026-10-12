mod broadcast;
mod discovery;
mod identity;
mod pairing;
mod prompt;
mod protocol;
mod storage;
mod tls;
mod trust;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use tokio::io::{AsyncBufRead, AsyncWriteExt, BufReader};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Semaphore;

use discovery::{Discovery, DiscoveryEvent, LocalDevice};
use identity::{Fingerprint, Identity};
use pairing::{Keys, Outcome};
use prompt::{Mode, Prompter};
use protocol::{escape_untrusted, read_message, write_message, Message};
use trust::{TrustStore, TrustedDevice};

/// TCP port of the TLS server. Fixed, so it can be opened in the firewall.
const DEFAULT_PORT: u16 = 47820;

/// Time an unpaired device has to request pairing.
const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "\
Usage:
  kizuna-desktop                 run the daemon (mDNS announcement + TLS server)
  kizuna-desktop pair <address>  pair with another device (ip[:port])
  kizuna-desktop devices         list paired devices
  kizuna-desktop unpair <id>     forget a device (the start of the ID is enough)";

/// State shared by the daemon's connections.
struct Daemon {
    fingerprint: Fingerprint,
    device_name: String,
    trust: TrustStore,
    prompter: Prompter,
    /// Only one pairing at a time (avoids queues of bogus requests).
    pairing_slot: Semaphore,
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(run());
    // Reading stdin (prompter) runs on a blocking thread that never finishes
    // on its own; without this, the process would hang on exit.
    runtime.shutdown_timeout(Duration::from_millis(100));
    result
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let dir = storage::config_dir()?;

    match args.as_slice() {
        [] => run_daemon(&dir).await,
        ["pair", address] => pair_with(&dir, address).await,
        ["devices"] => list_devices(&dir),
        ["unpair", id] => unpair(&dir, id),
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

async fn run_daemon(dir: &Path) -> Result<()> {
    println!("Kizuna desktop v{}", env!("CARGO_PKG_VERSION"));

    let device_name = device_name();
    let identity = Identity::load_or_create(dir, &device_name)?;
    println!("Device: {device_name} ({})", identity.device_id());
    println!("Fingerprint: {}", identity.fingerprint());

    let server = tls::Server::bind(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT)),
        &identity,
    )
    .await?;
    let port = server.local_addr()?.port();
    println!("TLS 1.3 server listening on port {port}");

    let local = LocalDevice {
        id: identity.device_id(),
        name: device_name.clone(),
        port,
    };
    // For networks without multicast (e.g. phone hotspots), also answer UDP probes.
    let responder = broadcast::Responder::bind(broadcast::bind_addr(), &local).await?;
    tokio::spawn(async move {
        if let Err(e) = responder.run().await {
            eprintln!("Discovery responder stopped: {e:#}");
        }
    });
    let discovery = Discovery::start(local)?;
    let mut browser = discovery.browse()?;
    tokio::spawn(async move {
        while let Some(event) = browser.next().await {
            match event {
                DiscoveryEvent::Found(d) => {
                    println!(
                        "Found: {} ({}) at {:?}:{}",
                        d.name, d.id, d.addresses, d.port
                    )
                }
                DiscoveryEvent::Lost { id } => println!("Left the network: {id}"),
            }
        }
    });

    let daemon = Arc::new(Daemon {
        fingerprint: identity.fingerprint(),
        device_name,
        trust: TrustStore::open(dir),
        prompter: Prompter::terminal(),
        pairing_slot: Semaphore::new(1),
    });

    let mut terminate = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            incoming = server.accept() => match incoming {
                Ok(incoming) => {
                    let daemon = daemon.clone();
                    tokio::spawn(async move {
                        let peer = incoming.peer();
                        let result = match incoming.handshake().await {
                            Ok(conn) => handle_connection(conn, peer, &daemon).await,
                            Err(e) => Err(e),
                        };
                        if let Err(e) = result {
                            // Second line of defence: the error may quote data from the other side.
                            eprintln!("Connection from {peer}: {}", escape_untrusted(&format!("{e:#}")));
                        }
                    });
                }
                Err(e) => eprintln!("Error accepting connection: {e:#}"),
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }

    println!("Shutting down...");
    discovery.shutdown().await;
    Ok(())
}

async fn handle_connection(conn: tls::Connection, peer: SocketAddr, daemon: &Daemon) -> Result<()> {
    let fingerprint = conn.peer_fingerprint;
    let (reader, mut writer) = tokio::io::split(conn.stream);
    let mut reader = BufReader::new(reader);

    if let Some(device) = daemon.trust.get(&fingerprint)? {
        println!("\"{}\" connected ({peer})", device.name);
        return session(&mut reader, &device.name).await;
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

    let Ok(_slot) = daemon.pairing_slot.try_acquire() else {
        write_message(&mut writer, &Message::PairReject).await?;
        bail!("pairing request rejected: another one is in progress");
    };
    let keys = Keys {
        own: daemon.fingerprint,
        peer: fingerprint,
    };
    let prompter = daemon.prompter.clone();
    let outcome = pairing::respond(
        &mut reader,
        &mut writer,
        keys,
        &daemon.device_name,
        peer_name,
        |prompt| async move { prompter.confirm(prompt, Mode::Enter).await },
    )
    .await?;

    match outcome {
        Outcome::Paired { peer_name } => {
            daemon
                .trust
                .add(TrustedDevice::new(fingerprint, peer_name.clone()))?;
            println!("Paired with \"{peer_name}\".");
            session(&mut reader, &peer_name).await
        }
        Outcome::RejectedLocally => {
            println!("Pairing rejected.");
            Ok(())
        }
        Outcome::RejectedByPeer => {
            println!("The other device rejected the pairing.");
            Ok(())
        }
    }
}

/// Connection with a paired device. For now it only logs the messages; the
/// features (notifications, clipboard, files) come next.
async fn session<R: AsyncBufRead + Unpin>(reader: &mut R, name: &str) -> Result<()> {
    while let Some(message) = read_message(reader).await? {
        println!("\"{name}\": {}", message.kind());
    }
    println!("\"{name}\" disconnected.");
    Ok(())
}

/// Pairs with the device at `address`, as the initiator.
async fn pair_with(dir: &Path, address: &str) -> Result<()> {
    let device_name = device_name();
    let identity = Identity::load_or_create(dir, &device_name)?;
    let trust = TrustStore::open(dir);
    let addr = resolve(address).await?;

    let conn = tls::connect(addr, &identity).await?;
    if let Some(device) = trust.get(&conn.peer_fingerprint)? {
        println!("Already paired with \"{}\".", device.name);
        return Ok(());
    }

    println!("Pairing with {addr}...");
    let fingerprint = conn.peer_fingerprint;
    let (reader, mut writer) = tokio::io::split(conn.stream);
    let mut reader = BufReader::new(reader);
    let prompter = Prompter::terminal();
    let keys = Keys {
        own: identity.fingerprint(),
        peer: fingerprint,
    };
    let outcome = pairing::initiate(
        &mut reader,
        &mut writer,
        keys,
        &device_name,
        |prompt| async move { prompter.confirm(prompt, Mode::Compare).await },
    )
    .await?;

    match outcome {
        Outcome::Paired { peer_name } => {
            trust.add(TrustedDevice::new(fingerprint, peer_name.clone()))?;
            println!("Paired with \"{peer_name}\".");
        }
        Outcome::RejectedLocally => println!("Pairing cancelled."),
        Outcome::RejectedByPeer => println!("The other device rejected the pairing."),
    }
    let _ = writer.shutdown().await;
    Ok(())
}

async fn resolve(address: &str) -> Result<SocketAddr> {
    let with_port = if address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:{DEFAULT_PORT}")
    };
    let mut addrs = tokio::net::lookup_host(&with_port)
        .await
        .with_context(|| format!("invalid address: {address}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("address has no results: {address}"))
}

fn list_devices(dir: &Path) -> Result<()> {
    let devices = TrustStore::open(dir).list()?;
    if devices.is_empty() {
        println!("No paired devices.");
    }
    for device in devices {
        println!("{}  {}", device.fingerprint.device_id(), device.name);
    }
    Ok(())
}

fn unpair(dir: &Path, id: &str) -> Result<()> {
    let store = TrustStore::open(dir);
    let matches: Vec<_> = store
        .list()?
        .into_iter()
        .filter(|d| d.fingerprint.to_string().starts_with(id))
        .collect();
    match matches.as_slice() {
        [] => bail!("no paired device with ID {id:?}"),
        [device] => {
            store.remove(&device.fingerprint.to_string())?;
            println!("\"{}\" has been forgotten.", device.name);
            Ok(())
        }
        _ => bail!("the ID {id:?} is ambiguous; type more characters"),
    }
}

/// Device name shown to others: the system hostname.
fn device_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Linux".to_string())
}
