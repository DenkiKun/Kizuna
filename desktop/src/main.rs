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
use protocol::{read_message, write_message, Message};
use trust::{TrustStore, TrustedDevice};

/// Porta TCP do servidor TLS. Fixa, para poder ser aberta na firewall.
const DEFAULT_PORT: u16 = 47820;

/// Tempo que um dispositivo não emparelhado tem para pedir emparelhamento.
const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "\
Uso:
  kizuna-desktop                 corre o daemon (anúncio mDNS + servidor TLS)
  kizuna-desktop pair <endereço> emparelha com outro dispositivo (ip[:porta])
  kizuna-desktop devices         lista os dispositivos emparelhados
  kizuna-desktop unpair <id>     esquece um dispositivo (início do ID chega)";

/// Estado partilhado pelas ligações do daemon.
struct Daemon {
    fingerprint: Fingerprint,
    device_name: String,
    trust: TrustStore,
    prompter: Prompter,
    /// Só um emparelhamento de cada vez (evita filas de pedidos falsos).
    pairing_slot: Semaphore,
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(run());
    // A leitura do stdin (prompter) corre numa thread bloqueante que nunca
    // termina sozinha; sem isto, o processo ficaria preso à saída.
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
    println!("Dispositivo: {device_name} ({})", identity.device_id());
    println!("Impressão digital: {}", identity.fingerprint());

    let server = tls::Server::bind(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT)),
        &identity,
    )
    .await?;
    let port = server.local_addr()?.port();
    println!("Servidor TLS 1.3 à escuta na porta {port}");

    let discovery = Discovery::start(LocalDevice {
        id: identity.device_id(),
        name: device_name.clone(),
        port,
    })?;
    let mut browser = discovery.browse()?;
    tokio::spawn(async move {
        while let Some(event) = browser.next().await {
            match event {
                DiscoveryEvent::Found(d) => {
                    println!(
                        "Encontrado: {} ({}) em {:?}:{}",
                        d.name, d.id, d.addresses, d.port
                    )
                }
                DiscoveryEvent::Lost { id } => println!("Saiu da rede: {id}"),
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
                            eprintln!("Ligação de {peer}: {e:#}");
                        }
                    });
                }
                Err(e) => eprintln!("Erro a aceitar ligação: {e:#}"),
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }

    println!("A terminar...");
    discovery.shutdown().await;
    Ok(())
}

async fn handle_connection(conn: tls::Connection, peer: SocketAddr, daemon: &Daemon) -> Result<()> {
    let fingerprint = conn.peer_fingerprint;
    let (reader, mut writer) = tokio::io::split(conn.stream);
    let mut reader = BufReader::new(reader);

    if let Some(device) = daemon.trust.get(&fingerprint)? {
        println!("«{}» ligou-se ({peer})", device.name);
        return session(&mut reader, &device.name).await;
    }

    // Um dispositivo desconhecido só pode pedir emparelhamento.
    let first = tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, read_message(&mut reader))
        .await
        .map_err(|_| anyhow!("dispositivo não emparelhado não pediu emparelhamento"))??;
    let peer_name = match first {
        Some(Message::PairRequest { device_name }) => device_name,
        Some(other) => bail!(
            "dispositivo não emparelhado enviou {}; ligação fechada",
            other.kind()
        ),
        None => return Ok(()),
    };

    let Ok(_slot) = daemon.pairing_slot.try_acquire() else {
        write_message(&mut writer, &Message::PairReject).await?;
        bail!("pedido de emparelhamento recusado: já há outro em curso");
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
            println!("Emparelhado com «{peer_name}».");
            session(&mut reader, &peer_name).await
        }
        Outcome::RejectedLocally => {
            println!("Emparelhamento recusado.");
            Ok(())
        }
        Outcome::RejectedByPeer => {
            println!("O outro dispositivo recusou o emparelhamento.");
            Ok(())
        }
    }
}

/// Ligação com um dispositivo emparelhado. Por agora só regista as mensagens;
/// as funcionalidades (notificações, clipboard, ficheiros) vêm a seguir.
async fn session<R: AsyncBufRead + Unpin>(reader: &mut R, name: &str) -> Result<()> {
    while let Some(message) = read_message(reader).await? {
        println!("«{name}»: {}", message.kind());
    }
    println!("«{name}» desligou-se.");
    Ok(())
}

/// Emparelha com o dispositivo em `address`, como iniciador.
async fn pair_with(dir: &Path, address: &str) -> Result<()> {
    let device_name = device_name();
    let identity = Identity::load_or_create(dir, &device_name)?;
    let trust = TrustStore::open(dir);
    let addr = resolve(address).await?;

    let conn = tls::connect(addr, &identity).await?;
    if let Some(device) = trust.get(&conn.peer_fingerprint)? {
        println!("Já estás emparelhado com «{}».", device.name);
        return Ok(());
    }

    println!("A emparelhar com {addr}...");
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
            println!("Emparelhado com «{peer_name}».");
        }
        Outcome::RejectedLocally => println!("Emparelhamento cancelado."),
        Outcome::RejectedByPeer => println!("O outro dispositivo recusou o emparelhamento."),
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
        .with_context(|| format!("endereço inválido: {address}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("endereço sem resultados: {address}"))
}

fn list_devices(dir: &Path) -> Result<()> {
    let devices = TrustStore::open(dir).list()?;
    if devices.is_empty() {
        println!("Nenhum dispositivo emparelhado.");
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
        [] => bail!("nenhum dispositivo emparelhado com o ID {id:?}"),
        [device] => {
            store.remove(&device.fingerprint.to_string())?;
            println!("«{}» foi esquecido.", device.name);
            Ok(())
        }
        _ => bail!("o ID {id:?} é ambíguo; escreve mais caracteres"),
    }
}

/// Nome do dispositivo mostrado aos outros: o hostname do sistema.
fn device_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Linux".to_string())
}
