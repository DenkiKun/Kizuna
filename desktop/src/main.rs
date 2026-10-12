mod discovery;
mod identity;
mod protocol;
mod tls;

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::signal::unix::{signal, SignalKind};

use discovery::{Discovery, DiscoveryEvent, LocalDevice};
use identity::Identity;

/// Porta TCP do servidor TLS. Fixa, para poder ser aberta na firewall.
const DEFAULT_PORT: u16 = 47820;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Kizuna desktop v{}", env!("CARGO_PKG_VERSION"));

    let device_name = device_name();
    let identity = Identity::load_or_create(&identity::default_dir()?, &device_name)?;
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
        name: device_name,
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

    let mut terminate = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            incoming = server.accept() => match incoming {
                Ok(incoming) => {
                    tokio::spawn(async move {
                        let peer = incoming.peer();
                        match incoming.handshake().await {
                            // Ainda não há emparelhamento: nenhum dispositivo é aceite.
                            Ok(mut conn) => {
                                println!(
                                    "Ligação de {peer} (certificado {}): dispositivo não emparelhado, a fechar",
                                    conn.peer_fingerprint
                                );
                                let _ = conn.stream.shutdown().await;
                            }
                            Err(e) => eprintln!("Ligação de {peer} recusada: {e:#}"),
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

/// Nome do dispositivo mostrado aos outros: o hostname do sistema.
fn device_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Linux".to_string())
}
