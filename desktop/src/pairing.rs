//! Pairing by comparing a 6-digit code (see docs/PROTOCOL.md).
//!
//! The code is derived from both certificates and two random nonces. The
//! responder commits to its nonce before seeing the initiator's, so neither
//! side (nor an attacker in the middle) can choose the code: an attack only
//! goes unnoticed with a probability of 1 in 1,000,000.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::identity::Fingerprint;
use crate::protocol::{clean_device_name, read_message, write_message, Message};

/// Maximum time for each automatic step of the protocol.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Time for the users to compare the code and decide.
const DECISION_TIMEOUT: Duration = Duration::from_secs(90);

const COMMIT_TAG: &[u8] = b"kizuna/v0/pair-commit";
const CODE_TAG: &[u8] = b"kizuna/v0/pair-code";

type Nonce = [u8; 32];

/// The fingerprints of both sides of the TLS connection.
#[derive(Debug, Clone, Copy)]
pub struct Keys {
    pub own: Fingerprint,
    pub peer: Fingerprint,
}

/// Confirmation code (0 to 999,999), shown as `123 456`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(u32);

impl Code {
    /// `true` if `input` is this code (whitespace is ignored).
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

/// What the user has to confirm.
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

/// Pairs as the initiator (the side that opened the connection).
///
/// `confirm` shows the code to the user and returns their decision; if the
/// other side rejects in the meantime, the future is dropped.
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
            decode::<32>(&commitment, "commitment")?,
        ),
        Message::PairReject => return Ok(Outcome::RejectedByPeer),
        other => bail!("expected pair.commit, got {}", other.kind()),
    };

    let own_nonce = random_nonce()?;
    write_message(writer, &nonce_message(&own_nonce)).await?;
    let peer_nonce = match recv(reader, STEP_TIMEOUT).await? {
        Message::PairNonce { nonce } => decode::<32>(&nonce, "nonce")?,
        Message::PairReject => return Ok(Outcome::RejectedByPeer),
        other => bail!("expected pair.nonce, got {}", other.kind()),
    };

    if commit(&peer_nonce, &keys.peer, &keys.own) != commitment {
        let _ = write_message(writer, &Message::PairReject).await;
        bail!("the nonce does not match the commitment (possible attack)");
    }

    let code = derive_code(&keys.own, &keys.peer, &own_nonce, &peer_nonce);
    decide(reader, writer, keys, peer_name, code, confirm).await
}

/// Pairs as the responder, after receiving `pair.request` from `peer_name`
/// (as it came in the message; it is cleaned here).
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
        other => bail!("expected pair.nonce, got {}", other.kind()),
    };
    write_message(writer, &nonce_message(&own_nonce)).await?;

    let code = derive_code(&keys.peer, &keys.own, &peer_nonce, &own_nonce);
    decide(reader, writer, keys, peer_name, code, confirm).await
}

/// Asks the local user for a decision and waits for the other side's.
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
    // The read cannot be cancelled midway (it would lose bytes), so it stays
    // pinned and is resumed after the local decision.
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
                other => bail!("expected pair.accept or pair.reject, got {}", other.kind()),
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
            other => bail!("expected pair.accept or pair.reject, got {}", other.kind()),
        }
    }
    Ok(Outcome::Paired { peer_name })
}

async fn recv<R: AsyncBufRead + Unpin>(reader: &mut R, timeout: Duration) -> Result<Message> {
    tokio::time::timeout(timeout, read_message(reader))
        .await
        .map_err(|_| anyhow!("the other device stopped responding"))??
        .ok_or_else(|| anyhow!("connection closed during pairing"))
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
        .map_err(|_| anyhow!("failed to generate a random nonce"))?;
    Ok(nonce)
}

fn decode<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    if value.len() != 2 * N || value.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!("invalid {what}");
    }
    hex::decode_to_slice(value, &mut bytes).map_err(|_| anyhow!("invalid {what}"))?;
    Ok(bytes)
}

/// Responder's commitment: SHA-256(tag ‖ Nb ‖ fp_responder ‖ fp_initiator).
fn commit(nonce: &Nonce, responder: &Fingerprint, initiator: &Fingerprint) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMMIT_TAG)
        .chain_update(nonce)
        .chain_update(responder.as_bytes())
        .chain_update(initiator.as_bytes())
        .finalize()
        .into()
}

/// Code: SHA-256(tag ‖ fp_initiator ‖ fp_responder ‖ Na ‖ Nb), first 4 bytes
/// as a big-endian integer, modulo 1,000,000.
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

    /// An in-memory connection between the two sides.
    fn link() -> ((Reader, Writer), (Reader, Writer)) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        ((BufReader::new(ar), aw), (BufReader::new(br), bw))
    }

    /// Runs both sides with the given decisions; returns (initiator, responder)
    /// and the prompts shown to each.
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
            "Phone",
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
    async fn both_accept_and_see_the_same_code() {
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
                peer_name: "Phone".into()
            }
        );

        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[0].code, prompts[1].code);
        let names: Vec<_> = prompts.iter().map(|p| p.peer_name.as_str()).collect();
        assert!(names.contains(&"PC") && names.contains(&"Phone"));
        let fps: Vec<_> = prompts.iter().map(|p| p.peer_fingerprint).collect();
        assert!(fps.contains(&fp(PC)) && fps.contains(&fp(PHONE)));
    }

    #[tokio::test]
    async fn code_changes_on_every_pairing() {
        let (_, _, first) = run(true, true).await;
        let (_, _, second) = run(true, true).await;
        assert_ne!(first[0].code, second[0].code);
    }

    #[tokio::test]
    async fn pc_rejects() {
        let (phone, pc, _) = run(true, false).await;
        assert_eq!(phone, Outcome::RejectedByPeer);
        assert_eq!(pc, Outcome::RejectedLocally);
    }

    #[tokio::test]
    async fn phone_rejects() {
        let (phone, pc, _) = run(false, true).await;
        assert_eq!(phone, Outcome::RejectedLocally);
        assert_eq!(pc, Outcome::RejectedByPeer);
    }

    #[tokio::test]
    async fn rejection_by_the_other_side_cancels_the_local_prompt() {
        let ((mut pr, mut pw), (mut cr, mut cw)) = link();
        // The PC user never answers; the phone rejects right away.
        let phone = initiate(
            &mut pr,
            &mut pw,
            Keys {
                own: fp(PHONE),
                peer: fp(PC),
            },
            "Phone",
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
                "Phone".into(),
                |_| std::future::pending::<bool>(),
            )
            .await
        };
        let result =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(phone, pc) })
                .await
                .expect("the PC kept waiting for the user");
        assert_eq!(result.0.unwrap(), Outcome::RejectedLocally);
        assert_eq!(result.1.unwrap(), Outcome::RejectedByPeer);
    }

    /// A responder that reveals a nonce other than the committed one is caught.
    #[tokio::test]
    async fn nonce_different_from_the_commitment_is_detected() {
        let ((mut pr, mut pw), (mut cr, mut cw)) = link();
        let phone = initiate(
            &mut pr,
            &mut pw,
            Keys {
                own: fp(PHONE),
                peer: fp(PC),
            },
            "Phone",
            |_| async { panic!("should not ask for confirmation") },
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
        assert!(err.to_string().contains("commitment"), "{err}");
        assert_eq!(last, Message::PairReject);
    }

    #[tokio::test]
    async fn out_of_order_message_is_an_error() {
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
    fn code_depends_on_all_inputs() {
        let (a, b, na, nb) = (fp(1), fp(2), [3; 32], [4; 32]);
        let base = derive_code(&a, &b, &na, &nb);
        assert_ne!(base, derive_code(&b, &a, &na, &nb));
        assert_ne!(base, derive_code(&a, &fp(5), &na, &nb));
        assert_ne!(base, derive_code(&a, &b, &[5; 32], &nb));
        assert_ne!(base, derive_code(&a, &b, &na, &[5; 32]));
        assert_eq!(base, derive_code(&a, &b, &na, &nb));
    }

    /// Shared test vector (docs/PROTOCOL.md); the Android app checks the same values.
    #[test]
    fn matches_the_protocol_test_vector() {
        let (initiator, responder) = (fp(0x11), fp(0x22));
        let (na, nb) = ([0x33; 32], [0x44; 32]);
        assert_eq!(
            hex::encode(commit(&nb, &responder, &initiator)),
            "6923165278d40d25bce69f08e8857bf93f90dc4eedf9077d6ea6e695fbf708a0"
        );
        assert_eq!(derive_code(&initiator, &responder, &na, &nb), Code(158474));
    }

    #[test]
    fn code_always_has_six_digits() {
        assert_eq!(Code(42).to_string(), "000 042");
        assert_eq!(Code(999_999).to_string(), "999 999");
    }

    #[test]
    fn code_typed_by_the_user() {
        let code = Code(42);
        assert!(code.matches("000042"));
        assert!(code.matches(" 000 042 "));
        assert!(!code.matches("42"));
        assert!(!code.matches("000043"));
        assert!(!code.matches("0000-42"));
        assert!(!code.matches(""));
    }

    #[test]
    fn invalid_nonce_is_rejected() {
        assert!(decode::<32>(&"ab".repeat(32), "nonce").is_ok());
        assert!(decode::<32>(&"AB".repeat(32), "nonce").is_err());
        assert!(decode::<32>("abcd", "nonce").is_err());
        assert!(decode::<32>(&"zz".repeat(32), "nonce").is_err());
    }
}
