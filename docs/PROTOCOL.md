# Protocolo (rascunho v0)

## Camadas

1. **Descoberta**: anúncio mDNS `_kizuna._tcp.local` com nome do dispositivo e porta.
2. **Transporte**: TCP com TLS 1.3. Cada dispositivo gera um par de chaves/certificado autoassinado na primeira execução.
3. **Emparelhamento**: troca de certificados e confirmação manual de um código curto derivado dos dois certificados (ou leitura de QR). Só dispositivos emparelhados são aceites depois.
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

## Tipos de mensagem (MVP)

| type | direção | descrição |
|------|---------|-----------|
| `pair.request` / `pair.accept` | ambos | emparelhamento |
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
