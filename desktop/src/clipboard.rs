//! The computer's clipboard: text from the phone goes in, and changes made
//! here go out to the connected phones.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

/// Longer texts are neither sent nor accepted whole; the message itself is
/// capped at 1 MiB anyway.
pub const MAX_CHARS: usize = 200_000;

/// How often the clipboard is read when there is no change notification
/// available (everywhere except Wayland with `wl-paste`).
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The system clipboard. The connection to the display is kept, because on
/// Wayland the clipboard contents are served for as long as it lives.
#[derive(Default)]
pub struct Clipboard {
    clipboard: Mutex<Option<arboard::Clipboard>>,
    /// The last text set or seen, so our own changes are not sent back and
    /// unchanged polls are ignored.
    last: Mutex<Option<String>>,
}

impl Clipboard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Blocking: call it off the async runtime.
    pub fn set_text(&self, text: &str) -> Result<()> {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(text.to_string());
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

    /// Calls `on_change` with every new clipboard text, on a background thread,
    /// for as long as the process lives. Texts over [`MAX_CHARS`] are skipped.
    pub fn watch(self: Arc<Self>, on_change: impl Fn(String) + Send + 'static) {
        thread::Builder::new()
            .name("clipboard-watch".into())
            .spawn(move || {
                let report = |text: String| {
                    if text.chars().count() > MAX_CHARS || !self.remember(&text) {
                        return;
                    }
                    on_change(text);
                };
                if std::env::var_os("WAYLAND_DISPLAY").is_some() && watch_with_wl_paste(&report) {
                    return;
                }
                self.poll(&report);
            })
            .expect("failed to start the clipboard watcher");
    }

    /// `true` if `text` differs from the last text set or seen.
    fn remember(&self, text: &str) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if last.as_deref() == Some(text) {
            return false;
        }
        *last = Some(text.to_string());
        true
    }

    fn poll(&self, report: &dyn Fn(String)) {
        loop {
            thread::sleep(POLL_INTERVAL);
            let text = {
                let mut guard = self.clipboard.lock().unwrap_or_else(|e| e.into_inner());
                if guard.is_none() {
                    *guard = arboard::Clipboard::new().ok();
                }
                guard.as_mut().and_then(|c| c.get_text().ok())
            };
            if let Some(text) = text {
                report(text);
            }
        }
    }
}

/// Uses `wl-paste --watch`, which is told by the compositor about every
/// change, so nothing is read until the clipboard actually changes. Returns
/// `false` if it cannot be started (then polling is used instead).
fn watch_with_wl_paste(report: &dyn Fn(String)) -> bool {
    let mut command = Command::new("wl-paste");
    command
        .args(["-t", "text", "--watch", "sh", "-c", r#"cat; printf '\0'"#])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // The helper must not outlive Kizuna (it only notices a closed pipe on the
    // next clipboard change), so the kernel ends it when this process exits.
    // SAFETY: prctl is async-signal-safe and touches nothing shared.
    unsafe {
        command.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let Some(mut stdout) = child.stdout.take() else {
        return false;
    };
    let mut buffer = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let n = match stdout.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buffer.extend_from_slice(&chunk[..n]);
        while let Some(end) = buffer.iter().position(|&b| b == 0) {
            let item = buffer.drain(..=end).collect::<Vec<u8>>();
            if let Ok(text) = String::from_utf8(item[..item.len() - 1].to_vec()) {
                report(text);
            }
        }
    }
    // wl-paste went away (e.g. the session ended); the caller can poll instead.
    let _ = child.wait();
    false
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
        assert_eq!(clean("a\tb\nc\0d"), "a\tb\ncd");
        assert_eq!(clean(&"x".repeat(MAX_CHARS + 5)).chars().count(), MAX_CHARS);
    }

    #[test]
    fn only_new_text_is_remembered() {
        let clipboard = Clipboard::new();
        assert!(clipboard.remember("a"));
        assert!(!clipboard.remember("a"));
        assert!(clipboard.remember("b"));
    }
}
