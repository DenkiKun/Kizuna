//! The Kizuna window: the same service as `kizuna-desktop daemon`, with the
//! pairing code typed in the window instead of the terminal.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use iced::futures::{SinkExt, Stream};
use iced::widget::{
    button, column, container, image, opaque, row, scrollable, space, stack, svg, text, text_input,
};
use iced::{
    border, gradient, window, Background, Border, Color, ContentFit, Element, Font, Length,
    Radians, Shadow, Size, Subscription, Task, Theme, Vector,
};
use tokio::sync::{mpsc, oneshot};

use crate::identity::Fingerprint;
use crate::pairing::Prompt;
use crate::service::{self, Event};
use crate::storage;
use crate::trust::{TrustStore, TrustedDevice};

const ACTIVITY_LINES: usize = 8;
const ICON: &[u8] = include_bytes!("../../data/icons/io.github.DenkiKun.Kizuna.svg");

pub fn run(dir: PathBuf) -> anyhow::Result<()> {
    iced::application(move || App::new(dir.clone()), App::update, App::view)
        .title("Kizuna")
        .subscription(App::subscription)
        .theme(|_: &App| Theme::Dark)
        .style(|_, _| iced::theme::Style {
            background_color: rgb(0x12, 0x0F, 0x2E),
            text_color: Color::WHITE,
        })
        .window(window::Settings {
            size: Size::new(980.0, 660.0),
            min_size: Some(Size::new(760.0, 540.0)),
            exit_on_close_request: false,
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

struct App {
    trust: TrustStore,
    this: Option<This>,
    paired: Vec<TrustedDevice>,
    connected: HashSet<Fingerprint>,
    activity: VecDeque<String>,
    pairing: Option<PendingPairing>,
    error: Option<String>,
    stop: Option<oneshot::Sender<()>>,
    closing: bool,
    backdrop: image::Handle,
    icon: svg::Handle,
}

impl App {
    fn new(dir: PathBuf) -> Self {
        let trust = TrustStore::open(&dir);
        let paired = trust.list().unwrap_or_default();
        Self {
            trust,
            this: None,
            paired,
            connected: HashSet::new(),
            activity: VecDeque::new(),
            pairing: None,
            error: None,
            stop: None,
            closing: false,
            backdrop: backdrop(960, 640),
            icon: svg::Handle::from_memory(ICON),
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
            Message::Service(event) => self.on_event(event),
            Message::ServiceStopped(error) => {
                if self.closing {
                    return iced::exit();
                }
                self.error = Some(error.unwrap_or_else(|| "The service stopped.".into()));
            }
            Message::PairingRequested { id, prompt, reply } => {
                self.pairing = Some(PendingPairing {
                    id,
                    prompt,
                    reply,
                    code: String::new(),
                });
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
                        self.log("Wrong code; pairing rejected.".into());
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
        }
        Task::none()
    }

    fn on_event(&mut self, event: Event) {
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
                self.log("Ready. Open Kizuna on your phone to connect.".into());
            }
            Event::Connected {
                name, fingerprint, ..
            } => {
                self.connected.insert(fingerprint);
                self.log(format!("{name} connected."));
            }
            Event::Disconnected { name, fingerprint } => {
                self.connected.remove(&fingerprint);
                self.log(format!("{name} disconnected."));
            }
            Event::Paired { name, fingerprint } => {
                self.reload_paired();
                self.connected.insert(fingerprint);
                self.log(format!("Paired with {name}."));
            }
            Event::PairingRejected => self.log("Pairing rejected.".into()),
            Event::PairingRejectedByPeer => {
                self.log("The other device rejected the pairing.".into())
            }
            Event::Received { name, kind } => self.log(format!("{name}: {kind}")),
            Event::ConnectionError { peer, error } => {
                self.log(format!("Connection from {}: {error}", peer.ip()))
            }
            Event::AcceptError(error) | Event::ResponderStopped(error) => self.log(error),
            Event::Found(_) | Event::Lost { .. } | Event::Stopping => {}
        }
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

    fn view(&self) -> Element<'_, Message> {
        let header = row![
            svg(self.icon.clone()).width(52).height(52),
            column![
                text("Kizuna").size(34).font(BOLD),
                text("Your phone and your PC, together.")
                    .size(15)
                    .color(SECONDARY),
            ]
            .spacing(2),
            space::horizontal(),
            self.status_pill(),
        ]
        .spacing(16)
        .align_y(iced::Alignment::Center);

        let body = row![
            card(self.this_pc()).width(Length::FillPortion(2)),
            card(self.devices()).width(Length::FillPortion(3)),
        ]
        .spacing(18);

        let mut content = column![header, body, card(self.activity())].spacing(22);
        if let Some(error) = &self.error {
            content = content.push(card(text(error.clone()).color(ACCENT)));
        }

        let page = scrollable(container(content).padding(28).width(Length::Fill));
        let mut layers = stack![
            image(self.backdrop.clone())
                .width(Length::Fill)
                .height(Length::Fill)
                .content_fit(ContentFit::Cover),
            page,
        ];
        if let Some(pairing) = &self.pairing {
            layers = layers.push(opaque(
                container(pairing_dialog(pairing))
                    .center(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.03, 0.02, 0.10, 0.55).into()),
                        ..container::Style::default()
                    }),
            ));
        }
        layers.into()
    }

    fn status_pill(&self) -> Element<'_, Message> {
        let (dot, label) = match &self.this {
            Some(this) => (GREEN, format!("Listening on port {}", this.port)),
            None if self.error.is_some() => (ACCENT, "Not running".to_string()),
            None => (SECONDARY, "Starting…".to_string()),
        };
        container(
            row![text("●").color(dot).size(12), text(label).size(14)]
                .spacing(8)
                .align_y(iced::Alignment::Center),
        )
        .padding([8, 16])
        .style(|_| translucent(18.0, 0.12))
        .into()
    }

    fn this_pc(&self) -> Element<'_, Message> {
        let Some(this) = &self.this else {
            return column![section("This PC"), text("Starting…").color(SECONDARY)]
                .spacing(12)
                .into();
        };
        column![
            section("This PC"),
            text(this.name.clone()).size(22).font(BOLD),
            labelled(
                "Device ID",
                text(this.id.clone()).font(Font::MONOSPACE).size(13)
            ),
            labelled(
                "Fingerprint",
                text(grouped(&this.fingerprint.to_string()))
                    .font(Font::MONOSPACE)
                    .size(12)
                    .color(SECONDARY),
            ),
        ]
        .spacing(14)
        .into()
    }

    fn devices(&self) -> Element<'_, Message> {
        let mut list = column![section("Paired devices")].spacing(10);
        if self.paired.is_empty() {
            list = list.push(
                text(
                    "No paired devices yet. Open Kizuna on your phone on the same \
                     network: this PC shows up on its own. Then type here the code \
                     the phone shows.",
                )
                .color(SECONDARY),
            );
        }
        for device in &self.paired {
            let online = self.connected.contains(&device.fingerprint);
            list = list.push(
                container(
                    row![
                        text("●").size(12).color(if online { GREEN } else { DIM }),
                        column![
                            text(device.name.clone()).size(17).font(BOLD),
                            text(if online { "Connected" } else { "Not connected" })
                                .size(13)
                                .color(SECONDARY),
                        ]
                        .spacing(2),
                        space::horizontal(),
                        pill_button("Forget", false).on_press(Message::Forget(device.fingerprint)),
                    ]
                    .spacing(14)
                    .align_y(iced::Alignment::Center),
                )
                .padding([12, 16])
                .style(|_| translucent(18.0, 0.07)),
            );
        }
        list.into()
    }

    fn activity(&self) -> Element<'_, Message> {
        let mut list = column![section("Activity")].spacing(8);
        if self.activity.is_empty() {
            list = list.push(text("Nothing yet.").color(SECONDARY));
        }
        for line in &self.activity {
            list = list.push(text(line.clone()).size(14).color(SECONDARY));
        }
        list.into()
    }
}

fn pairing_dialog(pairing: &PendingPairing) -> Element<'_, Message> {
    let ready = pairing.prompt.code.matches(&pairing.code);
    let submit = pill_button("Pair", true);
    let content = column![
        text(format!("Pairing request from {}", pairing.prompt.peer_name))
            .size(22)
            .font(BOLD),
        text("Type the code shown on the other device.").color(SECONDARY),
        text_input("000 000", &pairing.code)
            .on_input(Message::CodeChanged)
            .on_submit(Message::SubmitCode)
            .font(Font::MONOSPACE)
            .size(34)
            .padding([12, 18])
            .style(|_, status| field(status)),
        text(format!(
            "Fingerprint: {}",
            grouped(&pairing.prompt.peer_fingerprint.to_string())
        ))
        .font(Font::MONOSPACE)
        .size(11)
        .color(DIM),
        row![
            pill_button("Reject", false)
                .on_press(Message::RejectPairing)
                .width(Length::Fill),
            submit
                .on_press_maybe(ready.then_some(Message::SubmitCode))
                .width(Length::Fill),
        ]
        .spacing(12),
    ]
    .spacing(16)
    .max_width(460);
    container(content)
        .padding(28)
        .style(|_| translucent(28.0, 0.16))
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

// ---- Look ----------------------------------------------------------------

const SECONDARY: Color = Color::from_rgba(1.0, 1.0, 1.0, 0.70);
const DIM: Color = Color::from_rgba(1.0, 1.0, 1.0, 0.40);
const ACCENT: Color = Color::from_rgb(1.0, 0.56, 0.45);
const GREEN: Color = Color::from_rgb(0.36, 0.89, 0.62);
const BOLD: Font = Font {
    weight: iced::font::Weight::Semibold,
    ..Font::DEFAULT
};

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::from_rgb8(r, g, b)
}

/// Translucent card: light fill with a sheen at the top, hairline border and
/// a soft shadow.
fn translucent(radius: f32, fill: f32) -> container::Style {
    let sheen = gradient::Linear::new(Radians(std::f32::consts::PI))
        .add_stop(0.0, Color::from_rgba(1.0, 1.0, 1.0, fill + 0.08))
        .add_stop(1.0, Color::from_rgba(1.0, 1.0, 1.0, fill));
    container::Style {
        text_color: Some(Color::WHITE),
        background: Some(Background::Gradient(sheen.into())),
        border: Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.22),
            width: 1.0,
            radius: radius.into(),
        },
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.28),
            offset: Vector::new(0.0, 10.0),
            blur_radius: 30.0,
        },
        snap: false,
    }
}

fn card<'a>(content: impl Into<Element<'a, Message>>) -> container::Container<'a, Message> {
    container(content)
        .padding(22)
        .width(Length::Fill)
        .style(|_| translucent(24.0, 0.09))
}

fn section(title: &str) -> iced::widget::Text<'_> {
    text(title.to_uppercase())
        .size(12)
        .font(BOLD)
        .color(SECONDARY)
}

fn labelled<'a>(label: &'a str, value: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    column![text(label).size(12).color(DIM), value.into()]
        .spacing(4)
        .into()
}

fn pill_button(label: &str, accent: bool) -> button::Button<'_, Message> {
    button(text(label).size(15).font(BOLD).center())
        .padding([10, 22])
        .style(move |_, status| {
            let lift = match status {
                button::Status::Hovered => 0.06,
                button::Status::Pressed => -0.04,
                _ => 0.0,
            };
            let background = if accent {
                let alpha = if status == button::Status::Disabled {
                    0.35
                } else {
                    1.0
                };
                Background::Gradient(
                    gradient::Linear::new(Radians(std::f32::consts::FRAC_PI_2))
                        .add_stop(0.0, Color::from_rgba(1.0, 0.56 + lift, 0.45 + lift, alpha))
                        .add_stop(1.0, Color::from_rgba(0.94, 0.38 + lift, 0.48 + lift, alpha))
                        .into(),
                )
            } else {
                Color::from_rgba(1.0, 1.0, 1.0, 0.12 + lift).into()
            };
            button::Style {
                background: Some(background),
                text_color: if status == button::Status::Disabled {
                    DIM
                } else {
                    Color::WHITE
                },
                border: border::rounded(22)
                    .color(Color::from_rgba(
                        1.0,
                        1.0,
                        1.0,
                        if accent { 0.0 } else { 0.25 },
                    ))
                    .width(1),
                shadow: Shadow::default(),
                snap: false,
            }
        })
}

fn field(status: text_input::Status) -> text_input::Style {
    let focused = matches!(status, text_input::Status::Focused { .. });
    text_input::Style {
        background: Color::from_rgba(1.0, 1.0, 1.0, 0.08).into(),
        border: border::rounded(16)
            .color(if focused {
                ACCENT
            } else {
                Color::from_rgba(1.0, 1.0, 1.0, 0.25)
            })
            .width(1),
        icon: SECONDARY,
        placeholder: DIM,
        value: Color::WHITE,
        selection: Color::from_rgba(1.0, 0.56, 0.45, 0.4),
    }
}

/// Splits a fingerprint in groups of four for reading.
fn grouped(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A soft circle of color: center and radius (fractions of the width), color, strength.
type Glow = (f32, f32, f32, (u8, u8, u8), f32);

/// Deep gradient with soft color glows (same colors as the app icon).
fn backdrop(width: u32, height: u32) -> image::Handle {
    let stops = [(0x12, 0x0F, 0x2E), (0x1E, 0x18, 0x50), (0x0C, 0x2C, 0x3E)];
    let glows: [Glow; 3] = [
        (0.10, 0.05, 0.55, (0x7C, 0x6C, 0xFF), 0.60),
        (0.92, 0.30, 0.45, (0xFF, 0x8F, 0x73), 0.45),
        (0.30, 0.95, 0.50, (0x2F, 0xD3, 0xC4), 0.40),
    ];
    let (w, h) = (width as f32, height as f32);
    let mut pixels = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            let (fx, fy) = (x as f32 / w, y as f32 / h);
            let t = (fx + fy) / 2.0;
            let (a, b, k) = if t < 0.5 {
                (stops[0], stops[1], t * 2.0)
            } else {
                (stops[1], stops[2], t * 2.0 - 1.0)
            };
            let mut color = [lerp(a.0, b.0, k), lerp(a.1, b.1, k), lerp(a.2, b.2, k)];
            for (gx, gy, radius, (r, g, bl), strength) in glows {
                let dx = (fx - gx) * w;
                let dy = (fy - gy) * h;
                let d = (dx * dx + dy * dy).sqrt() / (radius * w);
                let weight = strength * (-2.2 * d * d).exp();
                for (channel, target) in color.iter_mut().zip([r, g, bl]) {
                    *channel += (f32::from(target) - *channel) * weight;
                }
            }
            pixels.extend(color.iter().map(|c| c.round().clamp(0.0, 255.0) as u8));
            pixels.push(255);
        }
    }
    image::Handle::from_rgba(width, height, pixels)
}

fn lerp(a: u8, b: u8, t: f32) -> f32 {
    f32::from(a) + (f32::from(b) - f32::from(a)) * t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_grouped_by_four() {
        assert_eq!(grouped("abcdef0123"), "abcd ef01 23");
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
