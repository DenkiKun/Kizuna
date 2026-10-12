# Protocolo (rascunho v0)

## Camadas

1. **Descoberta**: anúncio mDNS `_kizuna._tcp.local` com nome do dispositivo e porta.
2. **Transporte**: TCP com TLS 1.3. Cada dispositivo gera um par de chaves/certificado autoassinado na primeira execução.
3. **Emparelhamento**: troca de certificados e confirmação manual de um código curto derivado dos dois certificados (ou leitura de QR). Só dispositivos emparelhados são aceites depois.
4. **Mensagens**: JSON delimitado por novas linhas, cada uma com `type` e `body`.

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
