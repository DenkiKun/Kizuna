//! The computer's clipboard, for text the phone sends.

use std::sync::Mutex;

use anyhow::{Context, Result};

/// Longer texts are cut; the message itself is capped at 1 MiB anyway.
const MAX_CHARS: usize = 200_000;

/// Sets the system clipboard. The connection to the display is kept, because
/// on Wayland the clipboard contents are served for as long as it lives.
#[derive(Default)]
pub struct ClipboardSink {
    clipboard: Mutex<Option<arboard::Clipboard>>,
}

impl ClipboardSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Blocking: call it off the async runtime.
    pub fn set_text(&self, text: &str) -> Result<()> {
        let mut guard = self.clipboard.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(arboard::Clipboard::new().context("no clipboard available")?);
        }
        let clipboard = guard.as_mut().expect("just created");
        clipboard
            .set_text(text)
            .context("could not set the clipboard")?;
        Ok(())
    }
}

/// Text from the phone, trimmed to the size limit and without NUL bytes
/// (everything else, including newlines and tabs, is the user's own text).
pub fn clean(text: &str) -> String {
    text.chars()
        .filter(|&c| c != '\0')
        .take(MAX_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_text_but_drops_nul_and_caps_the_length() {
        assert_eq!(clean("a\tb\nc\0d"), "a\tb\nc".to_owned() + "d");
        assert_eq!(clean(&"x".repeat(MAX_CHARS + 5)).chars().count(), MAX_CHARS);
    }
}
