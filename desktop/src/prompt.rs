//! Pairing confirmation in the terminal.
//!
//! There are two modes:
//! - [`Mode::Enter`]: the user types the code they see on the other device.
//!   This is the daemon's mode: a late answer to an expired request never
//!   counts for another request (the code is different), and it forces the
//!   user to actually look at the other screen.
//! - [`Mode::Compare`]: the code is shown and the user answers y/N. This is
//!   the mode of the side that starts pairing (the other side types the code).
//!
//! Requests are shown one at a time; an answer only counts for the request
//! currently on screen, and is discarded if that request has already expired.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::pairing::Prompt;

/// How often to check whether the request on screen has expired.
const CHECK_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enter,
    Compare,
}

struct Request {
    prompt: Prompt,
    mode: Mode,
    reply: oneshot::Sender<bool>,
}

#[derive(Clone)]
pub struct Prompter {
    requests: mpsc::Sender<Request>,
}

impl Prompter {
    /// Prompter that reads answers from `input` and writes questions to `output`.
    pub fn spawn<I, O>(input: I, output: O) -> Self
    where
        I: AsyncBufRead + Unpin + Send + 'static,
        O: AsyncWrite + Unpin + Send + 'static,
    {
        let (requests, rx) = mpsc::channel(8);
        tokio::spawn(run(input, output, rx));
        Self { requests }
    }

    /// Prompter on the terminal (stdin/stdout).
    pub fn terminal() -> Self {
        Self::spawn(
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
    }

    /// Asks the user; `false` if they refuse or nobody can answer.
    /// Dropping the future cancels the question.
    pub async fn confirm(&self, prompt: Prompt, mode: Mode) -> bool {
        let (reply, answer) = oneshot::channel();
        let request = Request {
            prompt,
            mode,
            reply,
        };
        if self.requests.send(request).await.is_err() {
            return false;
        }
        answer.await.unwrap_or(false)
    }
}

async fn run<I, O>(input: I, mut output: O, mut requests: mpsc::Receiver<Request>)
where
    I: AsyncBufRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut lines = input.lines();
    let mut input_open = true;
    let mut queue: VecDeque<Request> = VecDeque::new();
    let mut shown = false;

    loop {
        while queue.front().is_some_and(|r| r.reply.is_closed()) {
            queue.pop_front();
            if shown {
                say(&mut output, "\nThe request expired or was cancelled.\n").await;
                shown = false;
            }
        }
        if !shown {
            if let Some(request) = queue.front() {
                say(&mut output, &question(request)).await;
                shown = true;
            }
        }

        tokio::select! {
            request = requests.recv() => match request {
                Some(request) if input_open => queue.push_back(request),
                Some(request) => { let _ = request.reply.send(false); }
                None => break,
            },
            line = lines.next_line(), if input_open => match line {
                Ok(Some(line)) => {
                    let Some(request) = queue.pop_front() else { continue };
                    shown = false;
                    if request.reply.is_closed() {
                        say(&mut output, "The request had already expired; answer ignored.\n").await;
                        continue;
                    }
                    let accepted = match request.mode {
                        Mode::Enter => request.prompt.code.matches(&line),
                        Mode::Compare => is_yes(&line),
                    };
                    let _ = request.reply.send(accepted);
                    let text = match (accepted, request.mode) {
                        (true, _) => "Confirmed.\n",
                        (false, Mode::Enter) if !line.trim().is_empty() => "Wrong code; pairing rejected.\n",
                        (false, _) => "Rejected.\n",
                    };
                    say(&mut output, text).await;
                }
                _ => {
                    input_open = false;
                    for request in queue.drain(..) {
                        let _ = request.reply.send(false);
                    }
                }
            },
            _ = tokio::time::sleep(CHECK_INTERVAL), if !queue.is_empty() => {}
        }
    }
}

fn question(request: &Request) -> String {
    let prompt = &request.prompt;
    let header = format!(
        "\nPairing request from \"{}\"\n  Fingerprint: {}\n",
        prompt.peer_name, prompt.peer_fingerprint
    );
    match request.mode {
        Mode::Enter => header + "Type the code shown on the other device (Enter rejects): ",
        Mode::Compare => format!(
            "{header}  Code: {}\nType this code on the other device. Accept? [y/N] ",
            prompt.code
        ),
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "sim"
    )
}

async fn say<O: AsyncWrite + Unpin>(output: &mut O, text: &str) {
    let _ = output.write_all(text.as_bytes()).await;
    let _ = output.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::Code;
    use tokio::io::{AsyncReadExt, BufReader, DuplexStream};

    fn prompt(name: &str, code: u32) -> Prompt {
        Prompt {
            peer_name: name.into(),
            peer_fingerprint: hex::encode([7; 32]).parse().unwrap(),
            code: Code::for_tests(code),
        }
    }

    fn setup() -> (Prompter, DuplexStream, DuplexStream) {
        let (user_in, prompter_in) = tokio::io::duplex(4096);
        let (prompter_out, user_out) = tokio::io::duplex(4096);
        let prompter = Prompter::spawn(BufReader::new(prompter_in), prompter_out);
        (prompter, user_in, user_out)
    }

    fn ask(prompter: &Prompter, prompt: Prompt, mode: Mode) -> tokio::task::JoinHandle<bool> {
        let prompter = prompter.clone();
        tokio::spawn(async move { prompter.confirm(prompt, mode).await })
    }

    async fn type_line(input: &mut DuplexStream, line: &str) {
        input
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn read_until(output: &mut DuplexStream, needle: &str) -> String {
        let mut seen = String::new();
        let mut buf = [0; 1024];
        while !seen.contains(needle) {
            let n = tokio::time::timeout(Duration::from_secs(5), output.read(&mut buf))
                .await
                .expect("the text did not appear")
                .unwrap();
            seen.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        seen
    }

    #[tokio::test]
    async fn right_code_confirms_and_is_not_shown() {
        let (prompter, mut input, mut output) = setup();
        let answer = ask(&prompter, prompt("Pixel", 123456), Mode::Enter);
        let text = read_until(&mut output, "Enter rejects").await;
        assert!(text.contains("\"Pixel\""), "{text}");
        assert!(!text.contains("123"), "the code must not appear: {text}");
        type_line(&mut input, "123 456").await;
        assert!(answer.await.unwrap());
    }

    #[tokio::test]
    async fn wrong_or_empty_code_rejects() {
        for reply in ["123457", "", "y"] {
            let (prompter, mut input, mut output) = setup();
            let answer = ask(&prompter, prompt("Pixel", 123456), Mode::Enter);
            read_until(&mut output, "Enter rejects").await;
            type_line(&mut input, reply).await;
            assert!(!answer.await.unwrap(), "{reply:?} was accepted");
        }
    }

    #[tokio::test]
    async fn compare_mode_shows_the_code_and_accepts_yes() {
        let (prompter, mut input, mut output) = setup();
        let answer = ask(&prompter, prompt("PC", 42), Mode::Compare);
        let text = read_until(&mut output, "[y/N]").await;
        assert!(text.contains("000 042"), "{text}");
        type_line(&mut input, "Yes").await;
        assert!(answer.await.unwrap());

        let answer = ask(&prompter, prompt("PC", 42), Mode::Compare);
        read_until(&mut output, "[y/N]").await;
        type_line(&mut input, "").await;
        assert!(!answer.await.unwrap());
    }

    #[tokio::test]
    async fn no_terminal_rejects() {
        let (prompter, input, _output) = setup();
        drop(input);
        assert!(!prompter.confirm(prompt("Pixel", 1), Mode::Enter).await);
    }

    #[tokio::test]
    async fn late_answer_never_approves_the_next_request() {
        let (prompter, mut input, mut output) = setup();

        // Request A expires without an answer.
        let a = tokio::time::timeout(
            Duration::from_millis(50),
            prompter.confirm(prompt("A", 111111), Mode::Enter),
        )
        .await;
        assert!(a.is_err());
        read_until(&mut output, "\"A\"").await;

        // Request B arrives, followed right away by the code the user typed for A.
        let b = ask(&prompter, prompt("B", 222222), Mode::Enter);
        type_line(&mut input, "111111").await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Depending on arrival order, the line is discarded or rejects B; it never approves it.
        if !b.is_finished() {
            read_until(&mut output, "\"B\"").await;
            type_line(&mut input, "").await;
        }
        assert!(!b.await.unwrap(), "A's code approved B");
    }
}
