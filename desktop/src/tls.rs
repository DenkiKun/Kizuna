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

/// Tempo máximo para um cliente concluir o handshake TLS.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Servidor TCP que só aceita TLS 1.3, com o certificado autoassinado deste
/// dispositivo, e exige um certificado ao cliente.
pub struct Server {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

/// Ligação TCP aceite, antes do handshake TLS.
pub struct Incoming {
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
}

/// Ligação TLS estabelecida (como servidor ou como cliente).
pub struct Connection {
    pub stream: TlsStream<TcpStream>,
    /// Impressão digital do certificado do outro lado. É com ela que a camada
    /// de emparelhamento decide se o dispositivo é aceite.
    pub peer_fingerprint: Fingerprint,
}

impl Server {
    pub async fn bind(addr: SocketAddr, identity: &Identity) -> Result<Self> {
        let config = server_config(identity)?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("falha a escutar em {addr}"))?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Aceita a próxima ligação TCP. O handshake é feito à parte, com
    /// [`Incoming::handshake`], para um cliente lento não bloquear os outros.
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
            .map_err(|_| anyhow!("handshake TLS expirou"))?
            .context("handshake TLS falhou")?;
        let peer_fingerprint = peer_fingerprint(stream.get_ref().1)?;
        Ok(Connection {
            stream: TlsStream::Server(stream),
            peer_fingerprint,
        })
    }
}

/// Liga a outro dispositivo Kizuna, apresentando o certificado deste.
///
/// O certificado do servidor não é validado aqui: quem chama tem de verificar
/// `peer_fingerprint` (contra a lista de emparelhados, ou emparelhando).
pub async fn connect(addr: SocketAddr, identity: &Identity) -> Result<Connection> {
    let config = client_config(Some(identity), &[&rustls::version::TLS13])?;
    let tcp = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("ligação a {addr} expirou"))?
        .with_context(|| format!("falha a ligar a {addr}"))?;
    // Os certificados não têm nomes; o SNI é fixo e ignorado.
    let name = ServerName::try_from("kizuna").expect("nome válido");
    let stream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| anyhow!("handshake TLS expirou"))?
    .context("handshake TLS falhou")?;
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
        .ok_or_else(|| anyhow!("o outro lado não apresentou certificado"))?;
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
        .context("certificado ou chave inválidos")?;
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
            .context("certificado ou chave inválidos")?,
        None => builder.with_no_client_auth(),
    })
}

/// Aceita qualquer certificado do outro lado, incluindo autoassinados.
///
/// Os dispositivos não têm uma autoridade de certificação comum: a confiança
/// vem do emparelhamento, que compara impressões digitais. Aqui o TLS garante
/// apenas que o outro lado possui a chave privada do certificado que
/// apresentou (a assinatura do handshake continua a ser verificada).
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
        // Nunca chamado: só é negociado TLS 1.3.
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
        Identity::load_or_create(dir.path(), "teste").unwrap()
    }

    async fn start_server() -> (Server, SocketAddr) {
        let server = Server::bind("127.0.0.1:0".parse().unwrap(), &identity())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        (server, addr)
    }

    /// Cliente com versões de TLS e certificado à escolha.
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
    async fn handshake_tls13_com_certificados_dos_dois_lados() {
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

        // Uma mensagem JSON por linha, como em docs/PROTOCOL.md.
        let msg = Message::ClipboardUpdate {
            text: "olá".into()
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
            Message::ClipboardUpdate { text } => assert_eq!(text, "olá"),
            other => panic!("mensagem inesperada: {other:?}"),
        }
    }

    #[tokio::test]
    async fn cliente_tls12_e_recusado() {
        let (server, addr) = start_server().await;
        let client_id = identity();

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        let client = raw_connect(addr, Some(&client_id), &[&rustls::version::TLS12]).await;

        assert!(client.is_err());
        let err = accepted
            .await
            .unwrap()
            .err()
            .expect("o servidor aceitou TLS 1.2");
        assert!(format!("{err:#}").contains("Tls12NotOffered"), "{err:#}");
    }

    #[tokio::test]
    async fn cliente_sem_certificado_e_recusado() {
        let (server, addr) = start_server().await;

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        // Em TLS 1.3 o cliente pode julgar o handshake concluído antes de o
        // servidor o recusar; o que conta é o lado do servidor.
        let _client = raw_connect(addr, None, &[&rustls::version::TLS13]).await;

        let err = accepted
            .await
            .unwrap()
            .err()
            .expect("o servidor aceitou o cliente");
        assert!(
            format!("{err:#}").contains("handshake TLS falhou"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn cliente_que_nao_fala_tls_expira_sem_bloquear_o_servidor() {
        let (server, addr) = start_server().await;
        let client_id = identity();

        // Primeiro cliente abre o TCP e fica calado.
        let _silent = TcpStream::connect(addr).await.unwrap();
        let silent = server.accept().await.unwrap();
        let silent_handshake = tokio::spawn(silent.handshake_within(Duration::from_millis(200)));

        // Um segundo cliente continua a ser atendido entretanto.
        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        connect(addr, &client_id).await.unwrap();
        assert!(accepted.await.unwrap().is_ok());

        let err = silent_handshake
            .await
            .unwrap()
            .err()
            .expect("handshake devia expirar");
        assert!(format!("{err}").contains("expirou"), "{err}");
    }
}
