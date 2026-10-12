# Kizuna

> An Android ↔ Linux link, built for immutable systems (Bazzite, Silverblue, SteamOS).

Kizuna connects your Android phone to your Linux PC over the local network, with an encrypted connection and no third-party servers.

## Why another "KDE Connect"?

- Easy to install on immutable systems (Flatpak, no package layering)
- No KDE/GNOME dependencies
- A documented, minimal protocol that is easy to audit
- Written in Rust (PC) and Kotlin (Android)

## MVP features (v0.1)

- [ ] Secure pairing (code/QR + key exchange)
- [ ] Notification sync (Android → PC)
- [ ] Clipboard sync (both ways)
- [ ] Sending and receiving files

## Roadmap

See [ROADMAP.md](ROADMAP.md). The protocol is described in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Privacy and security

- All traffic between paired devices is encrypted and authenticated
- Nothing leaves the local network; no telemetry
- Sensitive features (e.g. remote location) require **explicit consent** and **always show a visible notice** on the phone

## Layout

```
kizuna/
├── desktop/   # Rust daemon and CLI
├── android/   # Kotlin app
└── docs/      # protocol and architecture
```

## Contributing

Contributions are welcome. Please open an issue before making large changes.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
