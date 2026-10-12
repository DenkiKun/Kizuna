# Protocolo (rascunho v0)

## Camadas

1. **Descoberta**: anúncio mDNS `_kizuna._tcp.local` com nome do dispositivo e porta.
2. **Transporte**: TCP com TLS 1.3. Cada dispositivo gera um par de chaves/certificado autoassinado na primeira execução.
3. **Emparelhamento**: confirmação manual de um código de 6 dígitos derivado dos dois certificados e de nonces aleatórios (ver abaixo). Só dispositivos emparelhados são aceites depois.
4. **Mensagens**: JSON delimitado por novas linhas, cada uma com `type` e `body`.

## Identidade

- Chave ECDSA P-256 e certificado X.509 autoassinado, gerados na primeira execução (no PC: `$XDG_CONFIG_HOME/kizuna/identity.pem`, modo 0600).
- **Impressão digital**: SHA-256 do certificado (DER), em hexadecimal minúsculo (64 caracteres).
- **ID do dispositivo**: os primeiros 32 caracteres da impressão digital.

## Descoberta (mDNS / DNS-SD)

- Tipo de serviço: `_kizuna._tcp.local.`
- Nome da instância: o ID do dispositivo (ex.: `33a544b6…0ce5e._kizuna._tcp.local.`)
- Registo TXT:
  - `name`: nome legível do dispositivo
  - `v`: versão do protocolo (atualmente `0`); anúncios com outra versão são ignorados
- Porta anunciada: a do servidor TLS (no PC, por omissão `47820/tcp`)
- Por agora só são anunciados e usados endereços IPv4.

## Transporte (TLS)

- Só TLS 1.3; versões anteriores são recusadas no handshake.
- Autenticação mútua: o cliente **tem** de apresentar o seu certificado autoassinado.
- Não há autoridade de certificação: os certificados não são validados por cadeia. A confiança vem do emparelhamento, que compara impressões digitais; o TLS garante que o outro lado possui a chave privada do certificado apresentado.
- O cliente deve fixar (*pin*) a impressão digital do servidor depois do emparelhamento.
- Handshake com limite de 10 s.

## Mensagens

- Uma mensagem por linha: JSON em UTF-8 terminado em `\n`, no máximo 1 MiB.
- Formato: `{"type": "<tipo>", "body": {...}}`; mensagens sem conteúdo não têm `body` (ex.: `{"type":"pair.accept"}`).
- Os nomes de dispositivos recebidos são limpos antes de serem mostrados: sem caracteres de controlo nem de controlo bidirecional, no máximo 64 caracteres.

## Emparelhamento

Papéis: o **iniciador** (I) é quem abriu a ligação TLS (normalmente o telemóvel); o **respondedor** (R) é o servidor (normalmente o PC). `fp_I` e `fp_R` são as impressões digitais **em bytes** (32 bytes) dos certificados vistos no handshake TLS. Nonces, compromissos e impressões digitais viajam em hexadecimal minúsculo.

```
I → R  pair.request {device_name}
R → I  pair.commit  {device_name, commitment}   commitment = SHA256("kizuna/v0/pair-commit" ‖ Nb ‖ fp_R ‖ fp_I)
I → R  pair.nonce   {nonce: Na}                  Na: 32 bytes aleatórios
R → I  pair.nonce   {nonce: Nb}                  Nb: 32 bytes aleatórios
I      verifica o compromisso; se falhar, envia pair.reject e aborta
ambos  código = u32_big_endian(SHA256("kizuna/v0/pair-code" ‖ fp_I ‖ fp_R ‖ Na ‖ Nb)[0..4]) mod 1 000 000
ambos  pair.accept ou pair.reject, conforme a decisão do utilizador
```

- As etiquetas (`"kizuna/v0/pair-commit"`, `"kizuna/v0/pair-code"`) são os bytes ASCII, sem terminador.
- O código mostra-se com 6 dígitos, em dois grupos: `012 345`.
- **Porquê o compromisso**: R fixa Nb antes de ver Na, e I envia Na antes de ver Nb, por isso nenhum dos lados, nem um atacante no meio, consegue escolher o código. Um ataque só passa despercebido com probabilidade 1 em 1 000 000 por tentativa.
- **Confirmação**: o iniciador **mostra** o código e pede para aceitar; o respondedor pede ao utilizador que **escreva** o código que vê no iniciador. Assim o utilizador tem mesmo de comparar, e uma resposta atrasada a um pedido expirado nunca serve para outro.
- Cada lado envia a sua decisão assim que o utilizador decide e espera pela do outro. O emparelhamento só fica concluído se os dois aceitarem; nesse caso cada lado guarda a impressão digital e o nome do outro, e a ligação continua como sessão normal.
- Qualquer lado pode enviar `pair.reject` em qualquer passo (ex.: o PC recusa um segundo pedido enquanto há um em curso).
- Limites: 10 s para cada passo automático; 90 s para os utilizadores decidirem.
- Um dispositivo não emparelhado tem 10 s para enviar `pair.request`; qualquer outra mensagem fecha a ligação.
- Para emparelhar de novo um dispositivo já conhecido, é preciso esquecê-lo primeiro (no PC: `kizuna-desktop unpair <id>`).

## Tipos de mensagem (MVP)

| type | direção | descrição |
|------|---------|-----------|
| `pair.request` | I → R | pedido de emparelhamento (`device_name`) |
| `pair.commit` | R → I | nome do respondedor e compromisso com o seu nonce |
| `pair.nonce` | ambos | nonce aleatório (32 bytes) |
| `pair.accept` / `pair.reject` | ambos | decisão do utilizador |
| `notification.posted` | Android → PC | nova notificação (app, título, texto) |
| `notification.dismissed` | ambos | notificação fechada |
| `clipboard.update` | ambos | novo conteúdo da área de transferência |
| `file.offer` | ambos | proposta de envio (nome, tamanho, hash) |
| `file.accept` / `file.reject` | ambos | resposta |
| `file.chunk` | ambos | bloco de dados |

## Regras de segurança

- Rejeitar qualquer ligação de um dispositivo não emparelhado
- Pedir confirmação ao utilizador antes de aceitar ficheiros
- Nenhuma função sensível pode ser ativada sem consentimento explícito e aviso visível
