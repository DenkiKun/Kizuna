use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Tamanho máximo de uma mensagem (uma linha), para um outro lado malicioso
/// não esgotar a memória.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Mensagens do protocolo (ver docs/PROTOCOL.md). Uma por linha, em JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body")]
pub enum Message {
    #[serde(rename = "pair.request")]
    PairRequest { device_name: String },
    #[serde(rename = "pair.commit")]
    PairCommit {
        device_name: String,
        commitment: String,
    },
    #[serde(rename = "pair.nonce")]
    PairNonce { nonce: String },
    #[serde(rename = "pair.accept")]
    PairAccept,
    #[serde(rename = "pair.reject")]
    PairReject,
    #[serde(rename = "notification.posted")]
    NotificationPosted {
        app: String,
        title: String,
        text: String,
    },
    #[serde(rename = "clipboard.update")]
    ClipboardUpdate { text: String },
    #[serde(rename = "file.offer")]
    FileOffer {
        name: String,
        size: u64,
        sha256: String,
    },
}

impl Message {
    /// Nome do tipo, tal como aparece no campo `type`.
    pub fn kind(&self) -> &'static str {
        match self {
            Message::PairRequest { .. } => "pair.request",
            Message::PairCommit { .. } => "pair.commit",
            Message::PairNonce { .. } => "pair.nonce",
            Message::PairAccept => "pair.accept",
            Message::PairReject => "pair.reject",
            Message::NotificationPosted { .. } => "notification.posted",
            Message::ClipboardUpdate { .. } => "clipboard.update",
            Message::FileOffer { .. } => "file.offer",
        }
    }
}

/// Comprimento máximo de um nome de dispositivo, em caracteres.
const MAX_NAME_CHARS: usize = 64;

/// Limpa um nome de dispositivo vindo da rede antes de o mostrar: retira
/// caracteres de controlo (ex.: sequências de escape do terminal) e de
/// controlo bidirecional, e limita o comprimento.
pub fn clean_device_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_NAME_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "Dispositivo sem nome".to_string()
    } else {
        cleaned.to_string()
    }
}

/// Lê a próxima mensagem; `None` se a ligação foi fechada.
pub async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Message>> {
    let mut line = Vec::new();
    let limit = MAX_MESSAGE_LEN as u64 + 1;
    let n = match (&mut *reader)
        .take(limit)
        .read_until(b'\n', &mut line)
        .await
    {
        // Fechar a ligação sem close_notify entre mensagens é só uma
        // desconexão (ex.: o telemóvel perdeu o Wi-Fi).
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && line.is_empty() => 0,
        result => result?,
    };
    if n == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        if line.len() > MAX_MESSAGE_LEN {
            bail!("mensagem demasiado grande");
        }
        bail!("ligação fechada a meio de uma mensagem");
    }
    let message = serde_json::from_slice(&line).context("mensagem inválida")?;
    Ok(Some(message))
}

pub async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, message: &Message) -> Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn formato_json_das_mensagens() {
        let request = Message::PairRequest {
            device_name: "Pixel".into(),
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"type":"pair.request","body":{"device_name":"Pixel"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Message::PairAccept).unwrap(),
            r#"{"type":"pair.accept"}"#
        );
        let reject: Message = serde_json::from_str(r#"{"type":"pair.reject"}"#).unwrap();
        assert_eq!(reject, Message::PairReject);
    }

    #[test]
    fn nomes_vindos_da_rede_sao_limpos() {
        assert_eq!(clean_device_name("  Pixel 8  "), "Pixel 8");
        assert_eq!(clean_device_name("\u{1b}[2J\u{1b}[31mPC\n"), "[2J[31mPC");
        assert_eq!(clean_device_name("abc\u{202E}fdp.exe"), "abcfdp.exe");
        assert_eq!(clean_device_name("\u{7}\t"), "Dispositivo sem nome");
        assert_eq!(clean_device_name(&"é".repeat(100)).chars().count(), 64);
    }

    #[tokio::test]
    async fn varias_mensagens_numa_ligacao() {
        let mut buf = Vec::new();
        let messages = [
            Message::PairNonce { nonce: "ab".into() },
            Message::ClipboardUpdate {
                text: "linha 1\nlinha 2".into(),
            },
        ];
        for m in &messages {
            write_message(&mut buf, m).await.unwrap();
        }
        let mut reader = BufReader::new(&buf[..]);
        for m in &messages {
            assert_eq!(read_message(&mut reader).await.unwrap().as_ref(), Some(m));
        }
        assert_eq!(read_message(&mut reader).await.unwrap(), None);
    }

    #[tokio::test]
    async fn mensagem_demasiado_grande_e_recusada() {
        let huge = vec![b'x'; MAX_MESSAGE_LEN + 10];
        let err = read_message(&mut BufReader::new(&huge[..]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("demasiado grande"), "{err}");
    }

    #[tokio::test]
    async fn mensagem_cortada_ou_invalida_da_erro() {
        let cut = br#"{"type":"pair.accept"}"#;
        assert!(read_message(&mut BufReader::new(&cut[..])).await.is_err());
        let bad = b"{\"type\":\"nao.existe\"}\n";
        assert!(read_message(&mut BufReader::new(&bad[..])).await.is_err());
    }
}
