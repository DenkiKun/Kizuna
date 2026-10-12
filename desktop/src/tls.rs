use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{self, WebPkiSupportedAlgorithms};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, CommonState, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureScheme, SupportedProtocolVersion,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::identity::{Fingerprint, Identity};

/// Maximum time for a client to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP server that only accepts TLS 1.3, with this device's self-signed
/// certificate, and requires a certificate from the client.
pub struct Server {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

/// Accepted TCP connection, before the TLS handshake.
pub struct Incoming {
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
}

/// Established TLS connection (as server or as client).
pub struct Connection {
    pub stream: TlsStream<TcpStream>,
    /// Fingerprint of the other side's certificate. The pairing layer uses it
    /// to decide whether the device is accepted.
    pub peer_fingerprint: Fingerprint,
}

impl Server {
    pub async fn bind(addr: SocketAddr, identity: &Identity) -> Result<Self> {
        let config = server_config(identity)?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to listen on {addr}"))?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts the next TCP connection. The handshake is done separately, with
    /// [`Incoming::handshake`], so a slow client does not block the others.
    pub async fn accept(&self) -> Result<Incoming> {
        let (stream, peer) = self.listener.accept().await?;
        Ok(Incoming {
            stream,
            peer,
            acceptor: self.acceptor.clone(),
        })
    }
}

impl Incoming {
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub async fn handshake(self) -> Result<Connection> {
        self.handshake_within(HANDSHAKE_TIMEOUT).await
    }

    async fn handshake_within(self, timeout: Duration) -> Result<Connection> {
        let stream = tokio::time::timeout(timeout, self.acceptor.accept(self.stream))
            .await
            .map_err(|_| anyhow!("TLS handshake timed out"))?
            .context("TLS handshake failed")?;
        let peer_fingerprint = peer_fingerprint(stream.get_ref().1)?;
        Ok(Connection {
            stream: TlsStream::Server(stream),
            peer_fingerprint,
        })
    }
}

/// Connects to another Kizuna device, presenting this device's certificate.
///
/// The server's certificate is not validated here: the caller must check
/// `peer_fingerprint` (against the paired list, or by pairing).
pub async fn connect(addr: SocketAddr, identity: &Identity) -> Result<Connection> {
    let config = client_config(Some(identity), &[&rustls::version::TLS13])?;
    let tcp = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("connection to {addr} timed out"))?
        .with_context(|| format!("failed to connect to {addr}"))?;
    // Certificates have no names; the SNI is fixed and ignored.
    let name = ServerName::try_from("kizuna").expect("valid name");
    let stream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake timed out"))?
    .context("TLS handshake failed")?;
    let peer_fingerprint = peer_fingerprint(stream.get_ref().1)?;
    Ok(Connection {
        stream: TlsStream::Client(stream),
        peer_fingerprint,
    })
}

fn peer_fingerprint(state: &CommonState) -> Result<Fingerprint> {
    let cert = state
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| anyhow!("the other side did not present a certificate"))?;
    Ok(Fingerprint::of(cert))
}

fn server_config(identity: &Identity) -> Result<ServerConfig> {
    let provider = Arc::new(crypto::ring::default_provider());
    let client_verifier = Arc::new(AnyCert {
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("invalid certificate or key")?;
    Ok(config)
}

fn client_config(
    identity: Option<&Identity>,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<ClientConfig> {
    let provider = Arc::new(crypto::ring::default_provider());
    let verifier = Arc::new(AnyCert {
        algorithms: provider.signature_verification_algorithms,
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    Ok(match identity {
        Some(id) => builder
            .with_client_auth_cert(vec![id.cert.clone()], id.key.clone_key())
            .context("invalid certificate or key")?,
        None => builder.with_no_client_auth(),
    })
}

/// Accepts any certificate from the other side, including self-signed ones.
///
/// Devices have no common certificate authority: trust comes from pairing,
/// which compares fingerprints. Here TLS only guarantees that the other side
/// holds the private key of the certificate it presented (the handshake
/// signature is still verified).
#[derive(Debug)]
struct AnyCert {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for AnyCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Never called: only TLS 1.3 is negotiated.
        crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Message;
    use rustls::ProtocolVersion;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        Identity::load_or_create(dir.path(), "test").unwrap()
    }

    async fn start_server() -> (Server, SocketAddr) {
        let server = Server::bind("127.0.0.1:0".parse().unwrap(), &identity())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        (server, addr)
    }

    /// Client with a choice of TLS versions and certificate.
    async fn raw_connect(
        addr: SocketAddr,
        client: Option<&Identity>,
        versions: &[&'static SupportedProtocolVersion],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let config = client_config(client, versions).unwrap();
        let tcp = TcpStream::connect(addr).await?;
        let name = ServerName::try_from("kizuna").unwrap();
        TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
    }

    #[tokio::test]
    async fn tls13_handshake_with_certificates_on_both_sides() {
        let server_id = identity();
        let server = Server::bind("127.0.0.1:0".parse().unwrap(), &server_id)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let client_id = identity();

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        let mut client = connect(addr, &client_id).await.unwrap();
        let conn = accepted.await.unwrap().unwrap();

        assert_eq!(client.peer_fingerprint, server_id.fingerprint());
        assert_eq!(conn.peer_fingerprint, client_id.fingerprint());
        for stream in [&client.stream, &conn.stream] {
            assert_eq!(
                stream.get_ref().1.protocol_version(),
                Some(ProtocolVersion::TLSv1_3)
            );
        }

        // One JSON message per line, as in docs/PROTOCOL.md.
        let msg = Message::ClipboardUpdate {
            text: "héllo".into(),
        };
        let line = serde_json::to_string(&msg).unwrap() + "\n";
        client.stream.write_all(line.as_bytes()).await.unwrap();
        client.stream.flush().await.unwrap();

        let mut received = String::new();
        BufReader::new(conn.stream)
            .read_line(&mut received)
            .await
            .unwrap();
        match serde_json::from_str(&received).unwrap() {
            Message::ClipboardUpdate { text } => assert_eq!(text, "héllo"),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tls12_client_is_rejected() {
        let (server, addr) = start_server().await;
        let client_id = identity();

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        let client = raw_connect(addr, Some(&client_id), &[&rustls::version::TLS12]).await;

        assert!(client.is_err());
        let err = accepted
            .await
            .unwrap()
            .err()
            .expect("the server accepted TLS 1.2");
        assert!(format!("{err:#}").contains("Tls12NotOffered"), "{err:#}");
    }

    #[tokio::test]
    async fn client_without_certificate_is_rejected() {
        let (server, addr) = start_server().await;

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        // In TLS 1.3 the client may consider the handshake complete before the
        // server rejects it; what matters is the server side.
        let _client = raw_connect(addr, None, &[&rustls::version::TLS13]).await;

        let err = accepted
            .await
            .unwrap()
            .err()
            .expect("the server accepted the client");
        assert!(
            format!("{err:#}").contains("TLS handshake failed"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn client_that_does_not_speak_tls_times_out_without_blocking_the_server() {
        let (server, addr) = start_server().await;
        let client_id = identity();

        // The first client opens the TCP connection and stays silent.
        let _silent = TcpStream::connect(addr).await.unwrap();
        let silent = server.accept().await.unwrap();
        let silent_handshake = tokio::spawn(silent.handshake_within(Duration::from_millis(200)));

        // Meanwhile, a second client is still served.
        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        connect(addr, &client_id).await.unwrap();
        assert!(accepted.await.unwrap().is_ok());

        let err = silent_handshake
            .await
            .unwrap()
            .err()
            .expect("the handshake should have timed out");
        assert!(format!("{err}").contains("timed out"), "{err}");
    }
}
