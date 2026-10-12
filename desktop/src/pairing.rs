//! Emparelhamento por comparação de um código de 6 dígitos (ver docs/PROTOCOL.md).
//!
//! O código é derivado dos dois certificados e de dois nonces aleatórios. O
//! respondedor compromete-se com o seu nonce antes de ver o do iniciador, por
//! isso nenhum dos lados (nem um atacante no meio) consegue escolher o código:
//! um ataque só passa despercebido com probabilidade 1 em 1 000 000.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::identity::Fingerprint;
use crate::protocol::{clean_device_name, read_message, write_message, Message};

/// Tempo máximo para cada passo automático do protocolo.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Tempo para os utilizadores compararem o código e decidirem.
const DECISION_TIMEOUT: Duration = Duration::from_secs(90);

const COMMIT_TAG: &[u8] = b"kizuna/v0/pair-commit";
const CODE_TAG: &[u8] = b"kizuna/v0/pair-code";

type Nonce = [u8; 32];

/// As impressões digitais dos dois lados da ligação TLS.
#[derive(Debug, Clone, Copy)]
pub struct Keys {
    pub own: Fingerprint,
    pub peer: Fingerprint,
}

/// Código de confirmação (0 a 999 999), mostrado como `123 456`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(u32);

impl Code {
    /// `true` se `input` é este código (os espaços são ignorados).
    pub fn matches(&self, input: &str) -> bool {
        let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        digits.len() == 6
            && digits.bytes().all(|b| b.is_ascii_digit())
            && digits.parse() == Ok(self.0)
    }

    #[cfg(test)]
    pub fn for_tests(value: u32) -> Self {
        Self(value % 1_000_000)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// O que o utilizador tem de confirmar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub peer_name: String,
    pub peer_fingerprint: Fingerprint,
    pub code: Code,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Paired { peer_name: String },
    RejectedLocally,
    RejectedByPeer,
}

/// Emparelha como iniciador (o lado que abriu a ligação).
///
/// `confirm` mostra o código ao utilizador e devolve a sua decisão; se o outro
/// lado recusar entretanto, o futuro é abandonado.
pub async fn initiate<R, W, F, Fut>(
    reader: &mut R,
    writer: &mut W,
    keys: Keys,
    own_name: &str,
    confirm: F,
) -> Result<Outcome>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(Prompt) -> Fut,
    Fut: Future<Output = bool>,
{
    let request = Message::PairRequest {
        device_name: own_name.to_string(),
    };
    write_message(writer, &request).await?;

    let (peer_name, commitment) = match recv(reader, STEP_TIMEOUT).await? {
        Message::PairCommit {
            device_name,
            commitment,
        } => (
            clean_device_name(&device_name),
            decode::<32>(&commitment, "compromisso")?,
        ),
        Message::PairReject => return Ok(Outcome::RejectedByPeer),
        other => bail!("esperava pair.commit, recebi {}", other.kind()),
    };

    let own_nonce = random_nonce()?;
    write_message(writer, &nonce_message(&own_nonce)).await?;
    let peer_nonce = match recv(reader, STEP_TIMEOUT).await? {
        Message::PairNonce { nonce } => decode::<32>(&nonce, "nonce")?,
        Message::PairReject => return Ok(Outcome::RejectedByPeer),
        other => bail!("esperava pair.nonce, recebi {}", other.kind()),
    };

    if commit(&peer_nonce, &keys.peer, &keys.own) != commitment {
        let _ = write_message(writer, &Message::PairReject).await;
        bail!("o nonce não corresponde ao compromisso (possível ataque)");
    }

    let code = derive_code(&keys.own, &keys.peer, &own_nonce, &peer_nonce);
    decide(reader, writer, keys, peer_name, code, confirm).await
}

/// Emparelha como respondedor, depois de receber `pair.request` de `peer_name`
/// (tal como veio na mensagem; é limpo aqui).
pub async fn respond<R, W, F, Fut>(
    reader: &mut R,
    writer: &mut W,
    keys: Keys,
    own_name: &str,
    peer_name: String,
    confirm: F,
) -> Result<Outcome>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(Prompt) -> Fut,
    Fut: Future<Output = bool>,
{
    let peer_name = clean_device_name(&peer_name);
    let own_nonce = random_nonce()?;
    let commitment = commit(&own_nonce, &keys.own, &keys.peer);
    let commit_message = Message::PairCommit {
        device_name: own_name.to_string(),
        commitment: hex::encode(commitment),
    };
    write_message(writer, &commit_message).await?;

    let peer_nonce = match recv(reader, STEP_TIMEOUT).await? {
        Message::PairNonce { nonce } => decode::<32>(&nonce, "nonce")?,
        Message::PairReject => return Ok(Outcome::RejectedByPeer),
        other => bail!("esperava pair.nonce, recebi {}", other.kind()),
    };
    write_message(writer, &nonce_message(&own_nonce)).await?;

    let code = derive_code(&keys.peer, &keys.own, &peer_nonce, &own_nonce);
    decide(reader, writer, keys, peer_name, code, confirm).await
}

/// Pede a decisão ao utilizador local e espera pela do outro lado.
async fn decide<R, W, F, Fut>(
    reader: &mut R,
    writer: &mut W,
    keys: Keys,
    peer_name: String,
    code: Code,
    confirm: F,
) -> Result<Outcome>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(Prompt) -> Fut,
    Fut: Future<Output = bool>,
{
    let prompt = Prompt {
        peer_name: peer_name.clone(),
        peer_fingerprint: keys.peer,
        code,
    };
    // A leitura não pode ser cancelada a meio (perderia bytes), por isso fica
    // fixa e é retomada depois da decisão local.
    let peer_decision = recv(reader, DECISION_TIMEOUT);
    tokio::pin!(peer_decision);
    let local_decision = tokio::time::timeout(DECISION_TIMEOUT, confirm(prompt));
    tokio::pin!(local_decision);

    let mut peer_accepted = false;
    let accepted = tokio::select! {
        decision = &mut peer_decision => {
            match decision? {
                Message::PairAccept => peer_accepted = true,
                Message::PairReject => return Ok(Outcome::RejectedByPeer),
                other => bail!("esperava pair.accept ou pair.reject, recebi {}", other.kind()),
            }
            local_decision.await.unwrap_or(false)
        }
        decision = &mut local_decision => decision.unwrap_or(false),
    };

    if !accepted {
        let _ = write_message(writer, &Message::PairReject).await;
        return Ok(Outcome::RejectedLocally);
    }
    write_message(writer, &Message::PairAccept).await?;

    if !peer_accepted {
        match peer_decision.await? {
            Message::PairAccept => {}
            Message::PairReject => return Ok(Outcome::RejectedByPeer),
            other => bail!(
                "esperava pair.accept ou pair.reject, recebi {}",
                other.kind()
            ),
        }
    }
    Ok(Outcome::Paired { peer_name })
}

async fn recv<R: AsyncBufRead + Unpin>(reader: &mut R, timeout: Duration) -> Result<Message> {
    tokio::time::timeout(timeout, read_message(reader))
        .await
        .map_err(|_| anyhow!("o outro dispositivo deixou de responder"))??
        .ok_or_else(|| anyhow!("ligação fechada durante o emparelhamento"))
}

fn nonce_message(nonce: &Nonce) -> Message {
    Message::PairNonce {
        nonce: hex::encode(nonce),
    }
}

fn random_nonce() -> Result<Nonce> {
    let mut nonce = [0; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut nonce)
        .map_err(|_| anyhow!("falha a gerar um nonce aleatório"))?;
    Ok(nonce)
}

fn decode<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    if value.len() != 2 * N || value.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!("{what} inválido");
    }
    hex::decode_to_slice(value, &mut bytes).map_err(|_| anyhow!("{what} inválido"))?;
    Ok(bytes)
}

/// Compromisso do respondedor: SHA-256(tag ‖ Nb ‖ fp_respondedor ‖ fp_iniciador).
fn commit(nonce: &Nonce, responder: &Fingerprint, initiator: &Fingerprint) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMMIT_TAG)
        .chain_update(nonce)
        .chain_update(responder.as_bytes())
        .chain_update(initiator.as_bytes())
        .finalize()
        .into()
}

/// Código: SHA-256(tag ‖ fp_iniciador ‖ fp_respondedor ‖ Na ‖ Nb), primeiros
/// 4 bytes como inteiro big-endian, módulo 1 000 000.
fn derive_code(
    initiator: &Fingerprint,
    responder: &Fingerprint,
    initiator_nonce: &Nonce,
    responder_nonce: &Nonce,
) -> Code {
    let hash = Sha256::new()
        .chain_update(CODE_TAG)
        .chain_update(initiator.as_bytes())
        .chain_update(responder.as_bytes())
        .chain_update(initiator_nonce)
        .chain_update(responder_nonce)
        .finalize();
    let prefix = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    Code(prefix % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{BufReader, DuplexStream, ReadHalf, WriteHalf};

    type Reader = BufReader<ReadHalf<DuplexStream>>;
    type Writer = WriteHalf<DuplexStream>;

    fn fp(byte: u8) -> Fingerprint {
        hex::encode([byte; 32]).parse().unwrap()
    }

    const PHONE: u8 = 0xaa;
    const PC: u8 = 0xbb;

    /// Uma ligação em memória entre os dois lados.
    fn link() -> ((Reader, Writer), (Reader, Writer)) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        ((BufReader::new(ar), aw), (BufReader::new(br), bw))
    }

    /// Corre os dois lados com as decisões dadas; devolve (iniciador, respondedor)
    /// e os prompts mostrados a cada um.
    async fn run(phone_accepts: bool, pc_accepts: bool) -> (Outcome, Outcome, Vec<Prompt>) {
        let ((mut pr, mut pw), (mut cr, mut cw)) = link();
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let (p1, p2) = (prompts.clone(), prompts.clone());

        let phone = initiate(
            &mut pr,
            &mut pw,
            Keys {
                own: fp(PHONE),
                peer: fp(PC),
            },
            "Telemóvel",
            |prompt| async move {
                p1.lock().unwrap().push(prompt);
                phone_accepts
            },
        );
        let pc = async {
            let peer_name = match recv(&mut cr, STEP_TIMEOUT).await.unwrap() {
                Message::PairRequest { device_name } => device_name,
                other => panic!("{other:?}"),
            };
            respond(
                &mut cr,
                &mut cw,
                Keys {
                    own: fp(PC),
                    peer: fp(PHONE),
                },
                "PC",
                peer_name,
                |prompt| async move {
                    p2.lock().unwrap().push(prompt);
                    pc_accepts
                },
            )
            .await
        };
        let (phone, pc) = tokio::join!(phone, pc);
        let prompts = prompts.lock().unwrap().clone();
        (phone.unwrap(), pc.unwrap(), prompts)
    }

    #[tokio::test]
    async fn os_dois_aceitam_e_veem_o_mesmo_codigo() {
        let (phone, pc, prompts) = run(true, true).await;
        assert_eq!(
            phone,
            Outcome::Paired {
                peer_name: "PC".into()
            }
        );
        assert_eq!(
            pc,
            Outcome::Paired {
                peer_name: "Telemóvel".into()
            }
        );

        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[0].code, prompts[1].code);
        let names: Vec<_> = prompts.iter().map(|p| p.peer_name.as_str()).collect();
        assert!(names.contains(&"PC") && names.contains(&"Telemóvel"));
        let fps: Vec<_> = prompts.iter().map(|p| p.peer_fingerprint).collect();
        assert!(fps.contains(&fp(PC)) && fps.contains(&fp(PHONE)));
    }

    #[tokio::test]
    async fn codigo_muda_em_cada_emparelhamento() {
        let (_, _, first) = run(true, true).await;
        let (_, _, second) = run(true, true).await;
        assert_ne!(first[0].code, second[0].code);
    }

    #[tokio::test]
    async fn pc_recusa() {
        let (phone, pc, _) = run(true, false).await;
        assert_eq!(phone, Outcome::RejectedByPeer);
        assert_eq!(pc, Outcome::RejectedLocally);
    }

    #[tokio::test]
    async fn telemovel_recusa() {
        let (phone, pc, _) = run(false, true).await;
        assert_eq!(phone, Outcome::RejectedLocally);
        assert_eq!(pc, Outcome::RejectedByPeer);
    }

    #[tokio::test]
    async fn recusa_do_outro_lado_cancela_a_pergunta_local() {
        let ((mut pr, mut pw), (mut cr, mut cw)) = link();
        // O utilizador do PC nunca responde; o telemóvel recusa logo.
        let phone = initiate(
            &mut pr,
            &mut pw,
            Keys {
                own: fp(PHONE),
                peer: fp(PC),
            },
            "Telemóvel",
            |_| async { false },
        );
        let pc = async {
            recv(&mut cr, STEP_TIMEOUT).await.unwrap();
            respond(
                &mut cr,
                &mut cw,
                Keys {
                    own: fp(PC),
                    peer: fp(PHONE),
                },
                "PC",
                "Telemóvel".into(),
                |_| std::future::pending::<bool>(),
            )
            .await
        };
        let result =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(phone, pc) })
                .await
                .expect("o PC ficou à espera do utilizador");
        assert_eq!(result.0.unwrap(), Outcome::RejectedLocally);
        assert_eq!(result.1.unwrap(), Outcome::RejectedByPeer);
    }

    /// Um respondedor que revela um nonce diferente do comprometido é apanhado.
    #[tokio::test]
    async fn nonce_diferente_do_compromisso_e_detetado() {
        let ((mut pr, mut pw), (mut cr, mut cw)) = link();
        let phone = initiate(
            &mut pr,
            &mut pw,
            Keys {
                own: fp(PHONE),
                peer: fp(PC),
            },
            "Telemóvel",
            |_| async { panic!("não devia pedir confirmação") },
        );
        let attacker = async {
            recv(&mut cr, STEP_TIMEOUT).await.unwrap();
            let committed = [1; 32];
            let commitment = hex::encode(commit(&committed, &fp(PC), &fp(PHONE)));
            let msg = Message::PairCommit {
                device_name: "PC".into(),
                commitment,
            };
            write_message(&mut cw, &msg).await.unwrap();
            recv(&mut cr, STEP_TIMEOUT).await.unwrap();
            write_message(&mut cw, &nonce_message(&[2; 32]))
                .await
                .unwrap();
            recv(&mut cr, STEP_TIMEOUT).await.unwrap()
        };
        let (phone, last) = tokio::join!(phone, attacker);
        let err = phone.unwrap_err();
        assert!(err.to_string().contains("compromisso"), "{err}");
        assert_eq!(last, Message::PairReject);
    }

    #[tokio::test]
    async fn mensagem_fora_de_ordem_e_erro() {
        let ((_ir, mut iw), (mut rr, mut rw)) = link();
        write_message(&mut iw, &Message::PairAccept).await.unwrap();
        let err = respond(
            &mut rr,
            &mut rw,
            Keys {
                own: fp(PC),
                peer: fp(PHONE),
            },
            "PC",
            "x".into(),
            |_| async { true },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("pair.nonce"), "{err}");
    }

    #[test]
    fn codigo_depende_de_todas_as_entradas() {
        let (a, b, na, nb) = (fp(1), fp(2), [3; 32], [4; 32]);
        let base = derive_code(&a, &b, &na, &nb);
        assert_ne!(base, derive_code(&b, &a, &na, &nb));
        assert_ne!(base, derive_code(&a, &fp(5), &na, &nb));
        assert_ne!(base, derive_code(&a, &b, &[5; 32], &nb));
        assert_ne!(base, derive_code(&a, &b, &na, &[5; 32]));
        assert_eq!(base, derive_code(&a, &b, &na, &nb));
    }

    #[test]
    fn codigo_tem_sempre_seis_digitos() {
        assert_eq!(Code(42).to_string(), "000 042");
        assert_eq!(Code(999_999).to_string(), "999 999");
    }

    #[test]
    fn codigo_introduzido_pelo_utilizador() {
        let code = Code(42);
        assert!(code.matches("000042"));
        assert!(code.matches(" 000 042 "));
        assert!(!code.matches("42"));
        assert!(!code.matches("000043"));
        assert!(!code.matches("0000-42"));
        assert!(!code.matches(""));
    }

    #[test]
    fn nonce_invalido_e_recusado() {
        assert!(decode::<32>(&"ab".repeat(32), "nonce").is_ok());
        assert!(decode::<32>(&"AB".repeat(32), "nonce").is_err());
        assert!(decode::<32>("abcd", "nonce").is_err());
        assert!(decode::<32>(&"zz".repeat(32), "nonce").is_err());
    }
}
