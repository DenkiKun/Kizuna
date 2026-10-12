mod broadcast;
mod discovery;
mod gui;
mod identity;
mod pairing;
mod prompt;
mod protocol;
mod service;
mod storage;
mod tls;
mod trust;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::signal::unix::{signal, SignalKind};

use identity::Identity;
use pairing::{Keys, Outcome};
use prompt::{Mode, Prompter};
use service::{Event, DEFAULT_PORT};
use trust::{TrustStore, TrustedDevice};

const USAGE: &str = "\
Usage:
  kizuna-desktop                 open the Kizuna window
  kizuna-desktop daemon          run without a window (pairing codes typed in the terminal)
  kizuna-desktop pair <address>  pair with another device (ip[:port])
  kizuna-desktop devices         list paired devices
  kizuna-desktop unpair <id>     forget a device (the start of the ID is enough)";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let dir = storage::config_dir()?;

    // The window runs its own event loop (and async runtime) on the main thread.
    if args.is_empty() {
        return gui::run(dir);
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        match args.as_slice() {
            ["daemon"] => run_daemon(&dir).await,
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
    });
    // Reading stdin (prompter) runs on a blocking thread that never finishes
    // on its own; without this, the process would hang on exit.
    runtime.shutdown_timeout(Duration::from_millis(100));
    result
}

/// Runs the service with terminal output and pairing codes typed on stdin.
async fn run_daemon(dir: &Path) -> Result<()> {
    println!("Kizuna desktop v{}", env!("CARGO_PKG_VERSION"));
    let prompter = Prompter::terminal();
    let confirm: service::Confirm = Arc::new(move |prompt| {
        let prompter = prompter.clone();
        Box::pin(async move { prompter.confirm(prompt, Mode::Enter).await })
    });
    let mut terminate = signal(SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    };
    service::run(dir, Arc::new(print_event), confirm, shutdown).await
}

fn print_event(event: Event) {
    match event {
        Event::Started {
            device_name,
            device_id,
            fingerprint,
            port,
        } => {
            println!("Device: {device_name} ({device_id})");
            println!("Fingerprint: {fingerprint}");
            println!("TLS 1.3 server listening on port {port}");
        }
        Event::Found(d) => println!(
            "Found: {} ({}) at {:?}:{}",
            d.name, d.id, d.addresses, d.port
        ),
        Event::Lost { id } => println!("Left the network: {id}"),
        Event::Connected { name, peer, .. } => println!("\"{name}\" connected ({peer})"),
        Event::Disconnected { name, .. } => println!("\"{name}\" disconnected."),
        Event::Received { name, kind } => println!("\"{name}\": {kind}"),
        Event::Paired { name, .. } => println!("Paired with \"{name}\"."),
        Event::PairingRejected => println!("Pairing rejected."),
        Event::PairingRejectedByPeer => println!("The other device rejected the pairing."),
        Event::ConnectionError { peer, error } => eprintln!("Connection from {peer}: {error}"),
        Event::AcceptError(error) => eprintln!("Error accepting connection: {error}"),
        Event::ResponderStopped(error) => eprintln!("Discovery responder stopped: {error}"),
        Event::Stopping => println!("Shutting down..."),
    }
}

/// Pairs with the device at `address`, as the initiator.
async fn pair_with(dir: &Path, address: &str) -> Result<()> {
    let device_name = service::device_name();
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
