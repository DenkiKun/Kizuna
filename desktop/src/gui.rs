//! The Kizuna window: the same service as `kizuna-desktop daemon`, with the
//! pairing code typed in the window instead of the terminal.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use iced::futures::{SinkExt, Stream};
use iced::widget::{
    button, column, container, opaque, operation, row, scrollable, space, stack, svg, text,
    text_input,
};
use iced::{
    border, gradient, window, Alignment, Background, Border, Color, Element, Font, Length, Radians,
    Shadow, Size, Subscription, Task, Theme,
};
use tokio::sync::{mpsc, oneshot};

use crate::identity::Fingerprint;
use crate::pairing::Prompt;
use crate::service::{self, Event};
use crate::storage;
use crate::trust::{TrustStore, TrustedDevice};

const APP_ID: &str = "io.github.DenkiKun.Kizuna";
const ACTIVITY_LINES: usize = 6;
const CODE_INPUT: &str = "pairing-code";

const ICON: &[u8] = include_bytes!("../../data/icons/io.github.DenkiKun.Kizuna.svg");
const PHONE: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#fff" fill-rule="evenodd" d="M8 2h8a2.5 2.5 0 0 1 2.5 2.5v15A2.5 2.5 0 0 1 16 22H8a2.5 2.5 0 0 1-2.5-2.5v-15A2.5 2.5 0 0 1 8 2Zm0 1.6h8a.9.9 0 0 1 .9.9v15a.9.9 0 0 1-.9.9H8a.9.9 0 0 1-.9-.9v-15a.9.9 0 0 1 .9-.9ZM10.5 18h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 1 0-1.5Z"/></svg>"##;

pub fn run(dir: PathBuf) -> anyhow::Result<()> {
    iced::application(move || App::new(dir.clone()), App::update, App::view)
        .title("Kizuna")
        .subscription(App::subscription)
        .theme(|_: &App| Theme::Dark)
        .style(|_, _| iced::theme::Style {
            background_color: BACKGROUND,
            text_color: TEXT,
        })
        .window(window::Settings {
            size: Size::new(920.0, 620.0),
            min_size: Some(Size::new(720.0, 500.0)),
            exit_on_close_request: false,
            // Lets the desktop match the window to data/io.github.DenkiKun.Kizuna.desktop (and its icon).
            platform_specific: window::settings::PlatformSpecific {
                application_id: APP_ID.into(),
                ..Default::default()
            },
            ..window::Settings::default()
        })
        .run()
        .map_err(|e| anyhow!("{e}"))
}

/// A one-shot value that can travel inside a (cloneable) message.
#[derive(Debug)]
pub struct Handoff<T>(Arc<Mutex<Option<T>>>);

impl<T> Clone for Handoff<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Handoff<T> {
    fn new(value: T) -> Self {
        Self(Arc::new(Mutex::new(Some(value))))
    }

    fn take(&self) -> Option<T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    ServiceReady(Handoff<oneshot::Sender<()>>),
    Service(Event),
    ServiceStopped(Option<String>),
    PairingRequested {
        id: u64,
        prompt: Prompt,
        reply: Handoff<oneshot::Sender<bool>>,
    },
    PairingEnded(u64),
    CodeChanged(String),
    SubmitCode,
    RejectPairing,
    Forget(Fingerprint),
    CloseRequested,
    ForceExit,
    Screenshot(window::Screenshot),
}

struct PendingPairing {
    id: u64,
    prompt: Prompt,
    reply: Handoff<oneshot::Sender<bool>>,
    code: String,
}

struct This {
    name: String,
    id: String,
    fingerprint: Fingerprint,
    port: u16,
}

/// Open connections of a paired device (a reconnect may overlap the old one).
struct Online {
    connections: usize,
    address: IpAddr,
}

struct App {
    trust: TrustStore,
    this: Option<This>,
    paired: Vec<TrustedDevice>,
    online: HashMap<Fingerprint, Online>,
    activity: VecDeque<String>,
    pairing: Option<PendingPairing>,
    notice: Option<String>,
    error: Option<String>,
    stop: Option<oneshot::Sender<()>>,
    closing: bool,
    icon: svg::Handle,
    phone: svg::Handle,
}

impl App {
    fn new(dir: PathBuf) -> Self {
        let trust = TrustStore::open(&dir);
        let paired = trust.list().unwrap_or_default();
        Self {
            trust,
            this: None,
            paired,
            online: HashMap::new(),
            activity: VecDeque::new(),
            pairing: None,
            notice: None,
            error: None,
            stop: None,
            closing: false,
            icon: svg::Handle::from_memory(ICON),
            phone: svg::Handle::from_memory(PHONE),
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            Subscription::run(service_stream),
            window::close_requests().map(|_| Message::CloseRequested),
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ServiceReady(stop) => self.stop = stop.take(),
            Message::Service(event) => return self.on_event(event),
            Message::ServiceStopped(error) => {
                if self.closing {
                    return iced::exit();
                }
                self.error = Some(error.unwrap_or_else(|| "The service stopped.".into()));
            }
            Message::PairingRequested { id, prompt, reply } => {
                self.notice = None;
                self.pairing = Some(PendingPairing {
                    id,
                    prompt,
                    reply,
                    code: String::new(),
                });
                return operation::focus(CODE_INPUT).chain(screenshot_if_requested());
            }
            Message::PairingEnded(id) => {
                if self.pairing.as_ref().is_some_and(|p| p.id == id) {
                    self.pairing = None;
                }
            }
            Message::CodeChanged(code) => {
                if let Some(pairing) = &mut self.pairing {
                    // Digits and spaces only, at most "123 456".
                    if code.len() <= 7 && code.chars().all(|c| c.is_ascii_digit() || c == ' ') {
                        pairing.code = code;
                    }
                }
            }
            Message::SubmitCode => {
                if let Some(pairing) = self.pairing.take() {
                    let accepted = pairing.prompt.code.matches(&pairing.code);
                    if !accepted {
                        self.notice = Some(format!(
                            "Wrong code: pairing with {} was cancelled. Try again from the phone.",
                            pairing.prompt.peer_name
                        ));
                    }
                    if let Some(reply) = pairing.reply.take() {
                        let _ = reply.send(accepted);
                    }
                }
            }
            Message::RejectPairing => {
                if let Some(reply) = self.pairing.take().and_then(|p| p.reply.take()) {
                    let _ = reply.send(false);
                }
            }
            Message::Forget(fingerprint) => {
                if let Err(e) = self.trust.remove(&fingerprint.to_string()) {
                    self.error = Some(format!("{e:#}"));
                }
                self.reload_paired();
                self.log("Device forgotten.".into());
            }
            Message::CloseRequested => {
                self.closing = true;
                match self.stop.take() {
                    // Withdraw the network announcement before leaving, with a deadline.
                    Some(stop) => {
                        let _ = stop.send(());
                        return Task::perform(tokio::time::sleep(Duration::from_secs(2)), |_| {
                            Message::ForceExit
                        });
                    }
                    None => return iced::exit(),
                }
            }
            Message::ForceExit => return iced::exit(),
            Message::Screenshot(shot) => save_screenshot(&shot),
        }
        Task::none()
    }

    fn on_event(&mut self, event: Event) -> Task<Message> {
        match event {
            Event::Started {
                device_name,
                device_id,
                fingerprint,
                port,
            } => {
                self.this = Some(This {
                    name: device_name,
                    id: device_id,
                    fingerprint,
                    port,
                });
                self.log("Ready.".into());
                return screenshot_if_requested();
            }
            Event::Connected {
                name,
                fingerprint,
                peer,
            } => {
                let online = self.online.entry(fingerprint).or_insert(Online {
                    connections: 0,
                    address: peer.ip(),
                });
                online.connections += 1;
                online.address = peer.ip();
                self.log(format!("{name} connected."));
                return screenshot_if_requested();
            }
            Event::Disconnected { name, fingerprint } => {
                if let Some(online) = self.online.get_mut(&fingerprint) {
                    online.connections -= 1;
                    if online.connections == 0 {
                        self.online.remove(&fingerprint);
                        self.log(format!("{name} disconnected."));
                    }
                }
            }
            Event::Paired { name, .. } => {
                self.reload_paired();
                self.notice = None;
                self.log(format!("Paired with {name}."));
            }
            Event::PairingRejected => self.log("Pairing cancelled.".into()),
            Event::PairingRejectedByPeer => self.log("The phone cancelled the pairing.".into()),
            Event::Received { name, kind } => self.log(format!("{name}: {kind}")),
            Event::Notification { name, app, title } => {
                self.log(format!("{name} · {app}: {title}"))
            }
            Event::DesktopNotificationFailed(error) => {
                self.log(format!("Could not show a notification: {error}"))
            }
            Event::ClipboardReceived { name, chars } => {
                self.log(format!("{name} sent {chars} characters to the clipboard."))
            }
            Event::ClipboardFailed(error) => {
                self.log(format!("Could not set the clipboard: {error}"))
            }
            Event::ClipboardSent { chars, .. } => {
                self.log(format!("Clipboard sent to the phone ({chars} characters)."))
            }
            Event::ConnectionError { peer, error } => {
                self.log(format!("Connection from {}: {error}", peer.ip()))
            }
            Event::AcceptError(error) | Event::ResponderStopped(error) => self.log(error),
            Event::Found(_) | Event::Lost { .. } | Event::Stopping => {}
        }
        Task::none()
    }

    fn reload_paired(&mut self) {
        match self.trust.list() {
            Ok(list) => self.paired = list,
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    fn log(&mut self, line: String) {
        self.activity.push_front(line);
        self.activity.truncate(ACTIVITY_LINES);
    }

    // ---- View ----------------------------------------------------------

    fn view(&self) -> Element<'_, Message> {
        let header = row![
            svg(self.icon.clone()).width(30).height(30),
            text("Kizuna").size(20).font(MEDIUM),
            space::horizontal(),
            self.status(),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let mut main = column![self.devices()].spacing(16);
        if let Some(notice) = &self.notice {
            main = main.push(panel(text(notice.clone()).size(14).color(TEXT_SECONDARY)));
        }
        if let Some(error) = &self.error {
            main = main.push(panel(text(error.clone()).size(14).color(DANGER)));
        }
        main = main.push(self.activity());

        let body = row![
            main.width(Length::FillPortion(5)),
            column![self.this_computer()].width(Length::FillPortion(3)),
        ]
        .spacing(16);

        let page = scrollable(
            column![header, body]
                .spacing(24)
                .padding([22, 26])
                .width(Length::Fill),
        );

        let mut layers = stack![container(page).width(Length::Fill).height(Length::Fill)];
        if let Some(pairing) = &self.pairing {
            layers = layers.push(opaque(
                container(pairing_dialog(pairing))
                    .center(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.55).into()),
                        ..container::Style::default()
                    }),
            ));
        }
        layers.into()
    }

    fn status(&self) -> Element<'_, Message> {
        let (color, label) = match (&self.this, &self.error) {
            (Some(_), _) if !self.online.is_empty() => (SUCCESS, "Connected"),
            (Some(_), _) => (TEXT_TERTIARY, "Waiting for your phone"),
            (None, Some(_)) => (DANGER, "Not running"),
            (None, None) => (TEXT_TERTIARY, "Starting…"),
        };
        container(
            row![dot(color), text(label).size(13).color(TEXT_SECONDARY)]
                .spacing(8)
                .align_y(Alignment::Center),
        )
        .padding([6, 12])
        .style(|_| surface(10.0))
        .into()
    }

    fn devices(&self) -> Element<'_, Message> {
        let mut list = column![title("Devices")].spacing(4);
        if self.paired.is_empty() {
            list = list.push(
                column![
                    text("No devices yet").size(15).font(MEDIUM),
                    text(
                        "Open Kizuna on your phone, on the same network, and tap this \
                         computer. A pairing request will appear here.",
                    )
                    .size(14)
                    .color(TEXT_SECONDARY),
                ]
                .spacing(4)
                .padding([12, 0]),
            );
        }
        for (index, device) in self.paired.iter().enumerate() {
            if index > 0 {
                list = list.push(hairline());
            }
            let online = self.online.get(&device.fingerprint);
            let detail = match online {
                Some(online) => format!("Connected · {}", online.address),
                None => "Not connected".to_string(),
            };
            list = list.push(
                row![
                    svg(self.phone.clone())
                        .width(22)
                        .height(22)
                        .style(move |_, _| svg::Style {
                            color: Some(if online.is_some() {
                                ACCENT
                            } else {
                                TEXT_TERTIARY
                            }),
                        }),
                    column![
                        text(device.name.clone()).size(15).font(MEDIUM),
                        row![
                            dot(if online.is_some() {
                                SUCCESS
                            } else {
                                TEXT_TERTIARY
                            }),
                            text(detail).size(13).color(TEXT_SECONDARY),
                        ]
                        .spacing(6)
                        .align_y(Alignment::Center),
                    ]
                    .spacing(3),
                    space::horizontal(),
                    ghost_button("Forget").on_press(Message::Forget(device.fingerprint)),
                ]
                .spacing(14)
                .padding([10, 0])
                .align_y(Alignment::Center),
            );
        }
        panel(list).into()
    }

    fn activity(&self) -> Element<'_, Message> {
        let mut list = column![title("Activity")].spacing(6);
        if self.activity.is_empty() {
            list = list.push(text("Nothing yet.").size(14).color(TEXT_TERTIARY));
        }
        for line in &self.activity {
            list = list.push(text(line.clone()).size(14).color(TEXT_SECONDARY));
        }
        panel(list).into()
    }

    fn this_computer(&self) -> Element<'_, Message> {
        let Some(this) = &self.this else {
            return panel(column![
                title("This computer"),
                text("Starting…").color(TEXT_SECONDARY)
            ])
            .into();
        };
        panel(
            column![
                title("This computer"),
                text(this.name.clone()).size(17).font(MEDIUM),
                field_row("Device ID", short(&this.id)),
                field_row("Port", this.port.to_string()),
                column![
                    text("Fingerprint").size(12).color(TEXT_TERTIARY),
                    text(grouped(&this.fingerprint.to_string()))
                        .font(Font::MONOSPACE)
                        .size(11)
                        .color(TEXT_SECONDARY),
                ]
                .spacing(4),
            ]
            .spacing(12),
        )
        .into()
    }
}

fn pairing_dialog(pairing: &PendingPairing) -> Element<'_, Message> {
    let digits = pairing.code.chars().filter(char::is_ascii_digit).count();
    let content = column![
        text(format!("Pair with {}?", pairing.prompt.peer_name))
            .size(19)
            .font(MEDIUM),
        text("Type the 6-digit code shown on the phone.")
            .size(14)
            .color(TEXT_SECONDARY),
        text_input("000 000", &pairing.code)
            .id(CODE_INPUT)
            .on_input(Message::CodeChanged)
            .on_submit(Message::SubmitCode)
            .font(Font::MONOSPACE)
            .size(30)
            .padding([10, 16])
            .style(|_, status| code_field(status)),
        text(format!(
            "Phone fingerprint: {}",
            grouped(&pairing.prompt.peer_fingerprint.to_string())
        ))
        .font(Font::MONOSPACE)
        .size(11)
        .color(TEXT_TERTIARY),
        row![
            ghost_button("Cancel")
                .on_press(Message::RejectPairing)
                .width(Length::Fill),
            primary_button("Pair")
                .on_press_maybe((digits == 6).then_some(Message::SubmitCode))
                .width(Length::Fill),
        ]
        .spacing(10),
    ]
    .spacing(14);
    container(content)
        .padding(24)
        .max_width(460)
        .style(|_| container::Style {
            background: Some(Color::from_rgb8(0x1A, 0x1C, 0x22).into()),
            ..surface(18.0)
        })
        .into()
}

/// Runs the service and turns its events and confirmation requests into messages.
fn service_stream() -> impl Stream<Item = Message> {
    iced::stream::channel(
        64,
        async |mut output: iced::futures::channel::mpsc::Sender<Message>| {
            let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
            let (stop_tx, stop_rx) = oneshot::channel::<()>();
            let _ = output
                .send(Message::ServiceReady(Handoff::new(stop_tx)))
                .await;

            let events_tx = tx.clone();
            let events: service::EventSink = Arc::new(move |event| {
                let _ = events_tx.send(Message::Service(event));
            });
            let confirm_tx = tx.clone();
            let next_id = Arc::new(AtomicU64::new(0));
            let confirm: service::Confirm = Arc::new(move |prompt| {
                let tx = confirm_tx.clone();
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move {
                    let (reply, answer) = oneshot::channel();
                    let _ = tx.send(Message::PairingRequested {
                        id,
                        prompt,
                        reply: Handoff::new(reply),
                    });
                    // Closes the dialog however the question ends (answer, timeout, rejection).
                    let _ended = OnDrop(move || {
                        let _ = tx.send(Message::PairingEnded(id));
                    });
                    answer.await.unwrap_or(false)
                })
            });

            let stopped_tx = tx.clone();
            tokio::spawn(async move {
                let result = match storage::config_dir() {
                    Ok(dir) => {
                        service::run(&dir, events, confirm, async {
                            let _ = stop_rx.await;
                        })
                        .await
                    }
                    Err(e) => Err(e),
                };
                let _ = stopped_tx.send(Message::ServiceStopped(
                    result.err().map(|e| format!("{e:#}")),
                ));
            });
            drop(tx);

            while let Some(message) = rx.recv().await {
                if output.send(message).await.is_err() {
                    break;
                }
            }
        },
    )
}

struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

/// With `KIZUNA_SCREENSHOT=<file>`, the window saves a picture of itself when
/// it is ready, when a pairing request appears and when a device connects (raw RGBA; the size is
/// printed). Useful for documentation.
const SCREENSHOT_VAR: &str = "KIZUNA_SCREENSHOT";

fn screenshot_if_requested() -> Task<Message> {
    if std::env::var_os(SCREENSHOT_VAR).is_none() {
        return Task::none();
    }
    Task::perform(tokio::time::sleep(Duration::from_millis(800)), |_| ())
        .then(|_| window::latest())
        .and_then(window::screenshot)
        .map(Message::Screenshot)
}

fn save_screenshot(shot: &window::Screenshot) {
    let Some(path) = std::env::var_os(SCREENSHOT_VAR) else {
        return;
    };
    match std::fs::write(&path, &shot.rgba) {
        Ok(()) => println!(
            "Screenshot: {}x{} RGBA in {}",
            shot.size.width,
            shot.size.height,
            PathBuf::from(path).display()
        ),
        Err(e) => eprintln!("Could not save the screenshot: {e}"),
    }
}

// ---- Look ----------------------------------------------------------------

const BACKGROUND: Color = Color::from_rgb(0.067, 0.071, 0.086);
const TEXT: Color = Color::from_rgb(0.953, 0.957, 0.965);
const TEXT_SECONDARY: Color = Color::from_rgb(0.631, 0.651, 0.690);
const TEXT_TERTIARY: Color = Color::from_rgb(0.420, 0.439, 0.475);
const ACCENT: Color = Color::from_rgb(0.545, 0.522, 1.0);
const SUCCESS: Color = Color::from_rgb(0.290, 0.871, 0.502);
const DANGER: Color = Color::from_rgb(1.0, 0.45, 0.45);
const MEDIUM: Font = Font {
    weight: iced::font::Weight::Medium,
    ..Font::DEFAULT
};

/// Translucent surface with a hairline border.
fn surface(radius: f32) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Color::from_rgba(1.0, 1.0, 1.0, 0.045).into()),
        border: Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.09),
            width: 1.0,
            radius: radius.into(),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

fn panel<'a>(content: impl Into<Element<'a, Message>>) -> container::Container<'a, Message> {
    container(content)
        .padding([16, 18])
        .width(Length::Fill)
        .style(|_| surface(14.0))
}

fn title(label: &str) -> iced::widget::Text<'_> {
    text(label).size(13).font(MEDIUM).color(TEXT_SECONDARY)
}

fn field_row<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    row![
        text(label).size(13).color(TEXT_TERTIARY),
        space::horizontal(),
        text(value)
            .size(13)
            .font(Font::MONOSPACE)
            .color(TEXT_SECONDARY),
    ]
    .into()
}

fn hairline<'a>() -> Element<'a, Message> {
    container(space().height(1))
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgba(1.0, 1.0, 1.0, 0.07).into()),
            ..container::Style::default()
        })
        .into()
}

fn dot<'a>(color: Color) -> Element<'a, Message> {
    container(space().width(8).height(8))
        .style(move |_| container::Style {
            background: Some(color.into()),
            border: border::rounded(4),
            ..container::Style::default()
        })
        .into()
}

fn primary_button(label: &str) -> button::Button<'_, Message> {
    button(text(label).size(14).font(MEDIUM).center())
        .padding([9, 18])
        .style(|_, status| {
            let (fill, text_color) = match status {
                button::Status::Disabled => (
                    Color { a: 0.35, ..ACCENT },
                    Color::from_rgba(0.05, 0.06, 0.08, 0.6),
                ),
                button::Status::Hovered => (lighten(ACCENT, 0.06), BACKGROUND),
                button::Status::Pressed => (lighten(ACCENT, -0.06), BACKGROUND),
                button::Status::Active => (ACCENT, BACKGROUND),
            };
            button::Style {
                background: Some(fill.into()),
                text_color,
                border: border::rounded(10),
                shadow: Shadow::default(),
                snap: true,
            }
        })
}

fn ghost_button(label: &str) -> button::Button<'_, Message> {
    button(text(label).size(14).center())
        .padding([7, 14])
        .style(|_, status| {
            let fill = match status {
                button::Status::Hovered => 0.08,
                button::Status::Pressed => 0.12,
                _ => 0.0,
            };
            button::Style {
                background: Some(Color::from_rgba(1.0, 1.0, 1.0, fill).into()),
                text_color: if status == button::Status::Disabled {
                    TEXT_TERTIARY
                } else {
                    TEXT_SECONDARY
                },
                border: border::rounded(10)
                    .color(Color::from_rgba(1.0, 1.0, 1.0, 0.14))
                    .width(1),
                shadow: Shadow::default(),
                snap: true,
            }
        })
}

fn code_field(status: text_input::Status) -> text_input::Style {
    let focused = matches!(status, text_input::Status::Focused { .. });
    text_input::Style {
        background: Background::Gradient(
            gradient::Linear::new(Radians(std::f32::consts::PI))
                .add_stop(0.0, Color::from_rgba(1.0, 1.0, 1.0, 0.06))
                .add_stop(1.0, Color::from_rgba(1.0, 1.0, 1.0, 0.03))
                .into(),
        ),
        border: border::rounded(12)
            .color(if focused {
                ACCENT
            } else {
                Color::from_rgba(1.0, 1.0, 1.0, 0.14)
            })
            .width(1),
        icon: TEXT_SECONDARY,
        placeholder: TEXT_TERTIARY,
        value: TEXT,
        selection: Color { a: 0.35, ..ACCENT },
    }
}

fn lighten(color: Color, amount: f32) -> Color {
    Color::from_rgb(
        (color.r + amount).clamp(0.0, 1.0),
        (color.g + amount).clamp(0.0, 1.0),
        (color.b + amount).clamp(0.0, 1.0),
    )
}

/// Splits a fingerprint in groups of four for reading.
fn grouped(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first 16 characters of an ID, enough to recognise it.
fn short(id: &str) -> String {
    match id.get(..16) {
        Some(start) if id.len() > 16 => format!("{start}…"),
        _ => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_grouped_by_four() {
        assert_eq!(grouped("abcdef0123"), "abcd ef01 23");
    }

    #[test]
    fn long_ids_are_shortened() {
        assert_eq!(short("0123456789abcdef0123"), "0123456789abcdef…");
        assert_eq!(short("abc"), "abc");
    }

    #[test]
    fn handoff_gives_its_value_once() {
        let handoff = Handoff::new(5);
        let copy = handoff.clone();
        assert_eq!(copy.take(), Some(5));
        assert_eq!(handoff.take(), None);
    }

    #[test]
    fn on_drop_runs_once_when_dropped() {
        let count = Arc::new(AtomicU64::new(0));
        let c = count.clone();
        drop(OnDrop(move || {
            c.fetch_add(1, Ordering::Relaxed);
        }));
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
