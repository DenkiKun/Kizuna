# Protocol (draft v0)

## Layers

1. **Discovery**: mDNS announcement of `_kizuna._tcp.local` with the device name and port.
2. **Transport**: TCP with TLS 1.3. Each device generates a key pair and a self-signed certificate on first run.
3. **Pairing**: manual confirmation of a 6-digit code derived from both certificates and random nonces (see below). Afterwards, only paired devices are accepted.
4. **Messages**: newline-delimited JSON, each with a `type` and a `body`.

## Identity

- ECDSA P-256 key and self-signed X.509 certificate, generated on first run (on the PC: `$XDG_CONFIG_HOME/kizuna/identity.pem`, mode 0600).
- **Fingerprint**: SHA-256 of the certificate (DER), in lowercase hexadecimal (64 characters).
- **Device ID**: the first 32 characters of the fingerprint.

## Discovery (mDNS / DNS-SD)

- Service type: `_kizuna._tcp.local.`
- Instance name: the device ID (e.g. `33a544b6…0ce5e._kizuna._tcp.local.`)
- TXT record:
  - `name`: human-readable device name
  - `v`: protocol version (currently `0`); announcements with any other version are ignored
- Announced port: the TLS server's port (on the PC, `47820/tcp` by default)
- For now, only IPv4 addresses are announced and used.

## Transport (TLS)

- TLS 1.3 only; earlier versions are rejected during the handshake.
- Mutual authentication: the client **must** present its self-signed certificate.
- There is no certificate authority: certificates are not chain-validated. Trust comes from pairing, which compares fingerprints; TLS guarantees that the other side holds the private key of the certificate it presented.
- The client should pin the server's fingerprint after pairing.
- The handshake has a 10 s limit.

## Messages

- One message per line: UTF-8 JSON terminated by `\n`, at most 1 MiB.
- Format: `{"type": "<type>", "body": {...}}`; messages without content have no `body` (e.g. `{"type":"pair.accept"}`).
- Received device names are cleaned before being shown: no control or bidirectional control characters, at most 64 characters.

## Pairing

Roles: the **initiator** (I) is the side that opened the TLS connection (usually the phone); the **responder** (R) is the server (usually the PC). `fp_I` and `fp_R` are the fingerprints **as bytes** (32 bytes) of the certificates seen in the TLS handshake. Nonces, commitments and fingerprints are sent as lowercase hexadecimal.

```
I → R  pair.request {device_name}
R → I  pair.commit  {device_name, commitment}   commitment = SHA256("kizuna/v0/pair-commit" ‖ Nb ‖ fp_R ‖ fp_I)
I → R  pair.nonce   {nonce: Na}                  Na: 32 random bytes
R → I  pair.nonce   {nonce: Nb}                  Nb: 32 random bytes
I      checks the commitment; if it fails, sends pair.reject and aborts
both   code = u32_big_endian(SHA256("kizuna/v0/pair-code" ‖ fp_I ‖ fp_R ‖ Na ‖ Nb)[0..4]) mod 1 000 000
both   pair.accept or pair.reject, according to the user's decision
```

- The tags (`"kizuna/v0/pair-commit"`, `"kizuna/v0/pair-code"`) are their ASCII bytes, with no terminator.
- The code is shown as 6 digits in two groups: `012 345`.
- **Why the commitment**: R fixes Nb before seeing Na, and I sends Na before seeing Nb, so neither side, nor an attacker in the middle, can choose the code. An attack goes unnoticed with a probability of only 1 in 1,000,000 per attempt.
- **Confirmation**: the initiator **shows** the code and asks the user to accept; the responder asks the user to **type** the code shown on the initiator. This forces the user to actually compare, and a late answer to an expired request can never count for another one.
- Each side sends its decision as soon as its user decides, and waits for the other side's. Pairing only completes if both accept; in that case each side stores the other's fingerprint and name, and the connection continues as a normal session.
- Either side may send `pair.reject` at any step (e.g. the PC rejects a second request while one is in progress).
- Limits: 10 s for each automatic step; 90 s for the users to decide.
- An unpaired device has 10 s to send `pair.request`; any other message closes the connection.
- To pair an already known device again, it must be forgotten first (on the PC: `kizuna-desktop unpair <id>`).

## Message types (MVP)

| type | direction | description |
|------|-----------|-------------|
| `pair.request` | I → R | pairing request (`device_name`) |
| `pair.commit` | R → I | responder's name and commitment to its nonce |
| `pair.nonce` | both | random nonce (32 bytes) |
| `pair.accept` / `pair.reject` | both | the user's decision |
| `notification.posted` | Android → PC | new notification (app, title, text) |
| `notification.dismissed` | both | notification dismissed |
| `clipboard.update` | both | new clipboard contents |
| `file.offer` | both | offer to send a file (name, size, hash) |
| `file.accept` / `file.reject` | both | reply |
| `file.chunk` | both | block of data |

## Security rules

- Reject any connection from an unpaired device
- Ask the user for confirmation before accepting files
- No sensitive feature may be enabled without explicit consent and a visible notice
