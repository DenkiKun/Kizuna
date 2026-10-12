use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{self, WebPkiSupportedAlgorithms};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use rustls_pki_types::{CertificateDer, UnixTime};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::identity::{fingerprint, Identity};

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

/// Ligação TLS estabelecida.
pub struct Connection {
    pub stream: TlsStream<TcpStream>,
    /// Impressão digital SHA-256 do certificado do cliente. É com ela que a
    /// camada de emparelhamento decide se o dispositivo é aceite.
    pub peer_fingerprint: String,
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
        let peer_cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| anyhow!("o cliente não apresentou certificado"))?;
        let peer_fingerprint = fingerprint(peer_cert);
        Ok(Connection {
            stream,
            peer_fingerprint,
        })
    }
}

fn server_config(identity: &Identity) -> Result<ServerConfig> {
    let provider = Arc::new(crypto::ring::default_provider());
    let client_verifier = Arc::new(AnyClientCert {
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("certificado ou chave inválidos")?;
    Ok(config)
}

/// Aceita qualquer certificado de cliente, incluindo autoassinados.
///
/// Os dispositivos não têm uma autoridade de certificação comum: a confiança
/// vem do emparelhamento, que compara impressões digitais. Aqui o TLS garante
/// apenas que o cliente possui a chave privada do certificado que apresentou
/// (a assinatura do handshake continua a ser verificada).
#[derive(Debug)]
struct AnyClientCert {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyClientCert {
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
        // Nunca chamado: o servidor só negoceia TLS 1.3.
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
    use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
    use rustls::{CertificateError, ClientConfig, ProtocolVersion, SupportedProtocolVersion};
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::client::TlsStream as ClientTlsStream;
    use tokio_rustls::TlsConnector;

    /// Cliente de teste: aceita apenas o certificado do servidor com a impressão
    /// digital esperada (como fará um dispositivo emparelhado).
    #[derive(Debug)]
    struct PinnedServer {
        fingerprint: String,
        algorithms: WebPkiSupportedAlgorithms,
    }

    impl ServerCertVerifier for PinnedServer {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if fingerprint(end_entity) == self.fingerprint {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
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

    fn identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        Identity::load_or_create(dir.path(), "teste").unwrap()
    }

    async fn start_server() -> (Server, Identity) {
        let identity = identity();
        let server = Server::bind("127.0.0.1:0".parse().unwrap(), &identity)
            .await
            .unwrap();
        (server, identity)
    }

    async fn connect(
        addr: SocketAddr,
        server_fingerprint: String,
        client: Option<&Identity>,
        versions: &[&'static SupportedProtocolVersion],
    ) -> std::io::Result<ClientTlsStream<TcpStream>> {
        let provider = Arc::new(crypto::ring::default_provider());
        let verifier = Arc::new(PinnedServer {
            fingerprint: server_fingerprint,
            algorithms: provider.signature_verification_algorithms,
        });
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let config = match client {
            Some(id) => builder
                .with_client_auth_cert(vec![id.cert.clone()], id.key.clone_key())
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        let tcp = TcpStream::connect(addr).await?;
        let name = ServerName::try_from("kizuna").unwrap();
        TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
    }

    #[tokio::test]
    async fn handshake_tls13_com_certificados_dos_dois_lados() {
        let (server, server_id) = start_server().await;
        let addr = server.local_addr().unwrap();
        let client_id = identity();

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        let mut client = connect(
            addr,
            server_id.fingerprint(),
            Some(&client_id),
            &[&rustls::version::TLS13],
        )
        .await
        .unwrap();
        let conn = accepted.await.unwrap().unwrap();

        assert_eq!(
            client.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            conn.stream.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(conn.peer_fingerprint, client_id.fingerprint());

        // Uma mensagem JSON por linha, como em docs/PROTOCOL.md.
        let msg = Message::ClipboardUpdate {
            text: "olá".into()
        };
        let line = serde_json::to_string(&msg).unwrap() + "\n";
        client.write_all(line.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

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
        let (server, server_id) = start_server().await;
        let addr = server.local_addr().unwrap();
        let client_id = identity();

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        let client = connect(
            addr,
            server_id.fingerprint(),
            Some(&client_id),
            &[&rustls::version::TLS12],
        )
        .await;

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
        let (server, server_id) = start_server().await;
        let addr = server.local_addr().unwrap();

        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        // Em TLS 1.3 o cliente pode julgar o handshake concluído antes de o
        // servidor o recusar; o que conta é o lado do servidor.
        let _client = connect(
            addr,
            server_id.fingerprint(),
            None,
            &[&rustls::version::TLS13],
        )
        .await;

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
        let (server, server_id) = start_server().await;
        let addr = server.local_addr().unwrap();
        let client_id = identity();

        // Primeiro cliente abre o TCP e fica calado.
        let _silent = TcpStream::connect(addr).await.unwrap();
        let silent = server.accept().await.unwrap();
        let silent_handshake = tokio::spawn(silent.handshake_within(Duration::from_millis(200)));

        // Um segundo cliente continua a ser atendido entretanto.
        let accepted = tokio::spawn(async move { server.accept().await?.handshake().await });
        connect(
            addr,
            server_id.fingerprint(),
            Some(&client_id),
            &[&rustls::version::TLS13],
        )
        .await
        .unwrap();
        assert!(accepted.await.unwrap().is_ok());

        let err = silent_handshake
            .await
            .unwrap()
            .err()
            .expect("handshake devia expirar");
        assert!(format!("{err}").contains("expirou"), "{err}");
    }
}
