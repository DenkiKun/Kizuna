use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size of a message (one line), so a malicious peer cannot exhaust
/// memory.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Protocol messages (see docs/PROTOCOL.md). One per line, in JSON.
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
    /// Type name, as it appears in the `type` field.
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

/// Maximum length of a device name, in characters.
const MAX_NAME_CHARS: usize = 64;

/// Cleans a device name received from the network before showing it: removes
/// control characters (e.g. terminal escape sequences) and bidirectional
/// control characters, and limits the length.
pub fn clean_device_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|&c| !is_unsafe_char(c))
        .take(MAX_NAME_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "Unnamed device".to_string()
    } else {
        cleaned.to_string()
    }
}

/// Escapes text received from the network before including it in error or log
/// messages, so no escape sequence reaches the terminal.
pub fn escape_untrusted(text: &str) -> String {
    text.chars()
        .map(|c| {
            if is_unsafe_char(c) {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Control and bidirectional control characters.
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Reads the next message; `None` if the connection was closed.
pub async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Message>> {
    let mut line = Vec::new();
    let limit = MAX_MESSAGE_LEN as u64 + 1;
    let n = match (&mut *reader)
        .take(limit)
        .read_until(b'\n', &mut line)
        .await
    {
        // Closing the connection without close_notify between messages is
        // just a disconnection (e.g. the phone lost Wi-Fi).
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && line.is_empty() => 0,
        result => result?,
    };
    if n == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        if line.len() > MAX_MESSAGE_LEN {
            bail!("message too large");
        }
        bail!("connection closed in the middle of a message");
    }
    // serde's errors quote the received text (e.g. "unknown variant ...").
    let message = serde_json::from_slice(&line)
        .map_err(|e| anyhow!("invalid message: {}", escape_untrusted(&e.to_string())))?;
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
    fn json_message_format() {
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
    fn names_from_the_network_are_cleaned() {
        assert_eq!(clean_device_name("  Pixel 8  "), "Pixel 8");
        assert_eq!(clean_device_name("\u{1b}[2J\u{1b}[31mPC\n"), "[2J[31mPC");
        assert_eq!(clean_device_name("abc\u{202E}fdp.exe"), "abcfdp.exe");
        assert_eq!(clean_device_name("\u{7}\t"), "Unnamed device");
        assert_eq!(clean_device_name(&"é".repeat(100)).chars().count(), 64);
    }

    #[tokio::test]
    async fn invalid_message_error_does_not_carry_escapes_to_the_terminal() {
        let line = b"{\"type\":\"\\u001b[2J\\u001b]0;x\\u0007\\u202e\"}\n";
        let err = read_message(&mut BufReader::new(&line[..]))
            .await
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(!text.chars().any(is_unsafe_char), "{text:?}");
        assert!(text.contains("\\u{1b}[2J"), "{text}");
    }

    #[tokio::test]
    async fn several_messages_on_one_connection() {
        let mut buf = Vec::new();
        let messages = [
            Message::PairNonce { nonce: "ab".into() },
            Message::ClipboardUpdate {
                text: "line 1\nline 2".into(),
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
    async fn oversized_message_is_rejected() {
        let huge = vec![b'x'; MAX_MESSAGE_LEN + 10];
        let err = read_message(&mut BufReader::new(&huge[..]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn truncated_or_invalid_message_is_an_error() {
        let cut = br#"{"type":"pair.accept"}"#;
        assert!(read_message(&mut BufReader::new(&cut[..])).await.is_err());
        let bad = b"{\"type\":\"does.not.exist\"}\n";
        assert!(read_message(&mut BufReader::new(&bad[..])).await.is_err());
    }
}
