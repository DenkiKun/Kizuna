use serde::{Deserialize, Serialize};

/// Mensagens do protocolo (ver docs/PROTOCOL.md). Uma por linha, em JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "body")]
pub enum Message {
    #[serde(rename = "pair.request")]
    PairRequest { device_name: String },
    #[serde(rename = "pair.accept")]
    PairAccept,
    #[serde(rename = "notification.posted")]
    NotificationPosted { app: String, title: String, text: String },
    #[serde(rename = "clipboard.update")]
    ClipboardUpdate { text: String },
    #[serde(rename = "file.offer")]
    FileOffer { name: String, size: u64, sha256: String },
}
