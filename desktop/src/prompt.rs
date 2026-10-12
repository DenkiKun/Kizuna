//! Confirmação de emparelhamentos no terminal.
//!
//! Há dois modos:
//! - [`Mode::Enter`]: o utilizador escreve o código que vê no outro
//!   dispositivo. É o modo do daemon: uma resposta atrasada a um pedido
//!   expirado nunca serve para outro pedido (o código é diferente), e obriga a
//!   olhar mesmo para o outro ecrã.
//! - [`Mode::Compare`]: o código é mostrado e o utilizador responde s/N. É o
//!   modo de quem inicia o emparelhamento (o outro lado escreve o código).
//!
//! Os pedidos são mostrados um de cada vez; uma resposta só conta para o
//! pedido que está no ecrã, e é descartada se esse pedido já expirou.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::pairing::Prompt;

/// De quanto em quanto tempo se verifica se o pedido no ecrã expirou.
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
    /// Prompter que lê respostas de `input` e escreve perguntas em `output`.
    pub fn spawn<I, O>(input: I, output: O) -> Self
    where
        I: AsyncBufRead + Unpin + Send + 'static,
        O: AsyncWrite + Unpin + Send + 'static,
    {
        let (requests, rx) = mpsc::channel(8);
        tokio::spawn(run(input, output, rx));
        Self { requests }
    }

    /// Prompter no terminal (stdin/stdout).
    pub fn terminal() -> Self {
        Self::spawn(
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
    }

    /// Pergunta ao utilizador; `false` se recusar ou não houver quem responda.
    /// Abandonar o futuro cancela a pergunta.
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
                say(&mut output, "\nO pedido expirou ou foi cancelado.\n").await;
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
                        say(&mut output, "O pedido já tinha expirado; resposta ignorada.\n").await;
                        continue;
                    }
                    let accepted = match request.mode {
                        Mode::Enter => request.prompt.code.matches(&line),
                        Mode::Compare => is_yes(&line),
                    };
                    let _ = request.reply.send(accepted);
                    let text = match (accepted, request.mode) {
                        (true, _) => "Confirmado.\n",
                        (false, Mode::Enter) if !line.trim().is_empty() => "Código errado; emparelhamento recusado.\n",
                        (false, _) => "Recusado.\n",
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
        "\nPedido de emparelhamento de «{}»\n  Impressão digital: {}\n",
        prompt.peer_name, prompt.peer_fingerprint
    );
    match request.mode {
        Mode::Enter => header + "Escreve o código mostrado no outro dispositivo (Enter recusa): ",
        Mode::Compare => format!(
            "{header}  Código: {}\nEscreve este código no outro dispositivo. Aceitar? [s/N] ",
            prompt.code
        ),
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "s" | "sim" | "y" | "yes"
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
                .expect("o texto não apareceu")
                .unwrap();
            seen.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        seen
    }

    #[tokio::test]
    async fn codigo_certo_confirma_e_nao_e_mostrado() {
        let (prompter, mut input, mut output) = setup();
        let answer = ask(&prompter, prompt("Pixel", 123456), Mode::Enter);
        let text = read_until(&mut output, "Enter recusa").await;
        assert!(text.contains("«Pixel»"), "{text}");
        assert!(!text.contains("123"), "o código não pode aparecer: {text}");
        type_line(&mut input, "123 456").await;
        assert!(answer.await.unwrap());
    }

    #[tokio::test]
    async fn codigo_errado_ou_vazio_recusa() {
        for reply in ["123457", "", "s"] {
            let (prompter, mut input, mut output) = setup();
            let answer = ask(&prompter, prompt("Pixel", 123456), Mode::Enter);
            read_until(&mut output, "Enter recusa").await;
            type_line(&mut input, reply).await;
            assert!(!answer.await.unwrap(), "{reply:?} aceitou");
        }
    }

    #[tokio::test]
    async fn modo_comparar_mostra_o_codigo_e_aceita_sim() {
        let (prompter, mut input, mut output) = setup();
        let answer = ask(&prompter, prompt("PC", 42), Mode::Compare);
        let text = read_until(&mut output, "[s/N]").await;
        assert!(text.contains("000 042"), "{text}");
        type_line(&mut input, "Sim").await;
        assert!(answer.await.unwrap());

        let answer = ask(&prompter, prompt("PC", 42), Mode::Compare);
        read_until(&mut output, "[s/N]").await;
        type_line(&mut input, "").await;
        assert!(!answer.await.unwrap());
    }

    #[tokio::test]
    async fn sem_terminal_recusa() {
        let (prompter, input, _output) = setup();
        drop(input);
        assert!(!prompter.confirm(prompt("Pixel", 1), Mode::Enter).await);
    }

    #[tokio::test]
    async fn resposta_atrasada_nunca_aprova_o_pedido_seguinte() {
        let (prompter, mut input, mut output) = setup();

        // O pedido A expira sem resposta.
        let a = tokio::time::timeout(
            Duration::from_millis(50),
            prompter.confirm(prompt("A", 111111), Mode::Enter),
        )
        .await;
        assert!(a.is_err());
        read_until(&mut output, "«A»").await;

        // Chega o pedido B e, logo a seguir, o código que o utilizador escreveu para A.
        let b = ask(&prompter, prompt("B", 222222), Mode::Enter);
        type_line(&mut input, "111111").await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Conforme a ordem de chegada, a linha é descartada ou recusa B; nunca o aprova.
        if !b.is_finished() {
            read_until(&mut output, "«B»").await;
            type_line(&mut input, "").await;
        }
        assert!(!b.await.unwrap(), "o código de A aprovou B");
    }
}
