# Kizuna

> Ligação Android ↔ Linux, pensada para sistemas imutáveis (Bazzite, Silverblue, SteamOS).

Kizuna liga o teu telemóvel Android ao teu PC Linux pela rede local, com ligação cifrada e sem servidores de terceiros.

## Porquê outro "KDE Connect"?

- Instalação simples em sistemas imutáveis (Flatpak, sem layering de pacotes)
- Sem dependências do KDE/GNOME
- Protocolo documentado e minimalista, fácil de auditar
- Escrito em Rust (PC) e Kotlin (Android)

## Funcionalidades do MVP (v0.1)

- [ ] Emparelhamento seguro (código/QR + troca de chaves)
- [ ] Sincronização de notificações (Android → PC)
- [ ] Sincronização da área de transferência (bidirecional)
- [ ] Envio e receção de ficheiros

## Roadmap

Ver [ROADMAP.md](ROADMAP.md). Protocolo em [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Privacidade e segurança

- Todo o tráfego é cifrado e autenticado entre dispositivos emparelhados
- Nada sai da rede local; sem telemetria
- Funções sensíveis (ex.: localização remota) exigem **consentimento explícito** e mostram **sempre um aviso visível** no telemóvel

## Estrutura

```
kizuna/
├── desktop/   # daemon e CLI em Rust
├── android/   # app Kotlin
└── docs/      # protocolo e arquitetura
```

## Contribuir

Contribuições são bem-vindas. Abre uma issue antes de grandes alterações.

## Licença

GPL-3.0-or-later (a confirmar antes da primeira release).
