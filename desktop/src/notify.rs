//! Desktop notifications for what the phone forwards, through the desktop's
//! notification service (`org.freedesktop.Notifications` on D-Bus).

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use notify_rust::{Hint, Notification, NotificationHandle};

use crate::identity::Fingerprint;

const APP_ID: &str = "io.github.DenkiKun.Kizuna";

/// Limits on what is shown, so a flood of text cannot swamp the desktop.
const MAX_ID_CHARS: usize = 200;
const MAX_APP_CHARS: usize = 64;
const MAX_TITLE_CHARS: usize = 200;
const MAX_TEXT_CHARS: usize = 1000;

/// Handles kept per device, so the oldest can be forgotten when there are
/// too many (the desktop keeps showing them; they just cannot be dismissed
/// from the phone any more).
const MAX_TRACKED_PER_DEVICE: usize = 100;

/// A notification as the phone sent it, already cleaned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posted {
    pub id: String,
    pub app: String,
    pub title: String,
    pub text: String,
}

impl Posted {
    /// Cleans what came from the network: no control or bidirectional
    /// control characters (newlines stay in the text), bounded lengths.
    pub fn cleaned(id: &str, app: &str, title: &str, text: &str) -> Self {
        Self {
            id: clean(id, MAX_ID_CHARS, false),
            app: clean(app, MAX_APP_CHARS, false),
            title: clean(title, MAX_TITLE_CHARS, false),
            text: clean(text, MAX_TEXT_CHARS, true),
        }
    }
}

/// Shows the phone's notifications on the desktop and dismisses them when
/// the phone says so. The D-Bus calls block, so call this off the async
/// runtime (e.g. with `spawn_blocking`).
#[derive(Default)]
pub struct Notifier {
    shown: Mutex<HashMap<Fingerprint, Vec<(String, NotificationHandle)>>>,
}

impl Notifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shows a notification, replacing the one with the same id from the same
    /// device if it is still tracked.
    pub fn post(&self, device: Fingerprint, device_name: &str, posted: &Posted) -> Result<()> {
        let previous = self.take(device, &posted.id).map(|handle| handle.id());

        let mut notification = Notification::new();
        notification
            .appname("Kizuna")
            .summary(&posted.title)
            .body(&body(posted, device_name))
            .icon(APP_ID)
            .hint(Hint::DesktopEntry(APP_ID.to_string()));
        if let Some(id) = previous {
            notification.id(id);
        }
        let handle = notification
            .show()
            .context("the desktop notification service did not accept the notification")?;

        let mut shown = self.shown.lock().unwrap_or_else(|e| e.into_inner());
        let list = shown.entry(device).or_default();
        list.push((posted.id.clone(), handle));
        if list.len() > MAX_TRACKED_PER_DEVICE {
            list.remove(0);
        }
        Ok(())
    }

    /// Closes the desktop notification the phone dismissed, if it is tracked.
    pub fn dismiss(&self, device: Fingerprint, id: &str) {
        if let Some(handle) = self.take(device, id) {
            handle.close();
        }
    }

    fn take(&self, device: Fingerprint, id: &str) -> Option<NotificationHandle> {
        let mut shown = self.shown.lock().unwrap_or_else(|e| e.into_inner());
        let list = shown.get_mut(&device)?;
        let index = list.iter().position(|(tracked, _)| tracked == id)?;
        Some(list.remove(index).1)
    }
}

/// The body shown under the title: the text, then which app on which phone.
/// Notification bodies may be parsed as markup, so the text is escaped.
fn body(posted: &Posted, device_name: &str) -> String {
    let source = match (posted.app.is_empty(), device_name.is_empty()) {
        (false, false) => format!("{} · {}", posted.app, device_name),
        (false, true) => posted.app.clone(),
        (true, _) => device_name.to_string(),
    };
    let text = escape_markup(&posted.text);
    if text.is_empty() {
        format!("<i>{}</i>", escape_markup(&source))
    } else {
        format!("{text}\n<i>{}</i>", escape_markup(&source))
    }
}

fn escape_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn clean(text: &str, max_chars: usize, keep_newlines: bool) -> String {
    let cleaned: String = text
        .chars()
        .filter(|&c| (keep_newlines && c == '\n') || !is_unsafe_char(c))
        .take(max_chars)
        .collect();
    cleaned.trim().to_string()
}

/// Control and bidirectional control characters.
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_from_the_phone_is_cleaned() {
        let posted = Posted::cleaned(
            "0|com.app|1|null",
            "\u{1b}[2JWhatsApp",
            "  Hi\u{202E}  ",
            "line 1\nline 2\u{7}",
        );
        assert_eq!(posted.app, "[2JWhatsApp");
        assert_eq!(posted.title, "Hi");
        assert_eq!(posted.text, "line 1\nline 2");
        assert_eq!(
            Posted::cleaned("", "", "", &"x".repeat(5000)).text.len(),
            MAX_TEXT_CHARS
        );
    }

    #[test]
    fn body_escapes_markup_and_names_the_source() {
        let posted = Posted::cleaned("1", "Mail", "Subject", "a <b> & c");
        assert_eq!(
            body(&posted, "Phone"),
            "a &lt;b&gt; &amp; c\n<i>Mail · Phone</i>"
        );
        let empty = Posted::cleaned("1", "", "Subject", "");
        assert_eq!(body(&empty, "Phone"), "<i>Phone</i>");
    }
}
