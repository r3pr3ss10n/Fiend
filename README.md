# Fiend

A pretty fast yet stealth proxy that disguises traffic as normal TLS 1.3 connections.

Named after [_The Fiend with Twenty Faces_](https://en.wikipedia.org/wiki/The_Fiend_with_Twenty_Faces) by Edogawa Ranpo — a master of disguise.

## Concept

The main point of app is stealth. Fiend uses a raw captured ClientHello as a byte-level template and replaces only the cryptographic fields that must
change per-connection. Everything else stays byte-for-byte identical, so JA3, JA4, and all other
fingerprinting vectors are indistinguishable from the original.

Templates can be captured from any application with various network stacks that speaks TLS 1.3 — like any platform browsers, native apps APIs, telemetry, anything. 
Each user can have a unique fingerprint sourced from a
real app on the wire, making tunnel traffic extremely hard to single out. The server relays
the real ServerHello and certificate chain from the disguise host, applies traffic padding, and
enforces replay protection — the session is indistinguishable from normal TLS 1.3.

## Quick start

### Fingerprint setup

You need to have [Wireshark](https://www.wireshark.org/) installed.

1. Open Wireshark, select your network interface and start capturing
2. Open application you want to take fingerprint of
3. Stop capturing, in the search field of Wireshark enter `tls.handshake.type == 1`. It will show you all ClientHellos that have been captured. Select the one you need according to the SNI
4. Select `Transport Layer Security`, then right click on `TLSv1.3 Record Layer: Handshake Protocol: Client Hello` and select `Export Packet Bytes...`. Export it as `app.bin`
5. Feed the binary to the Fiend.

```bash
./fiend fingerprint app.bin
```

You will get the `app.json` template that later will be used in the config.

Hint: That's the simplest guide. Search the internet about connecting your mobile device to Wireshark. Don't use Android emulator unless your desktop is arm64 (like Apple Silicon)!

## Server setup

Generate the key:

```bash
openssl rand -hex 32
```

Clone the repository:

```bash
git clone https://github.com/r3pr3ss10n/fiend
```

```bash
cd fiend
```

Create configuration `server-config.json`:

```json
{
  "bind": "0.0.0.0:443",
  "key": "<your-key>",
  "disguise": "<domain-from-fingerprint>"
}
```

Start (assumes you have [Docker](https://docs.docker.com/engine/install/ubuntu/) installed):

```bash
docker compose up -d --build
```

### Server tuning

For best throughput on high-latency links, raise the kernel TCP buffer limits:

```bash
cat >> /etc/sysctl.d/99-fiend.conf << 'EOF'
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
sysctl -p /etc/sysctl.d/99-fiend.conf
```

## Client setup

Create configuration `config.json`:

```json
{
  "server": "your-server-ip:443",
  "key": "<your-key>",
  "fingerprint": "app"
}
```

Launch the client:

```bash
fiend client config.json
```

Configure your browser or system to use SOCKS5 proxy at `127.0.0.1:1080`.

To use a custom listen address:

```json
{
  "server": "your-server-ip:443",
  "key": "<your-key>",
  "fingerprint": "app",
  "listen": "127.0.0.1:9050"
}
```

## Config fields

| Field         | Description                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------- |
| `key`         | Shared master key (hex, 64 chars).                                                                 |
| `fingerprint` | Path to fingerprint template. Required on client; optional on server.                              |
| `disguise`    | Domain for certificate relay and probe forwarding. Required on server unless `fingerprint` is set. |
| `server`      | Server address. Client only.                                                                       |
| `bind`        | Listen address. Server only, default `0.0.0.0:443`.                                                |
| `listen`      | SOCKS5 listen address. Client only, default `127.0.0.1:1080`.                                      |

## SOCKS5

Fiend exposes a local SOCKS5 proxy with support for:

- **CONNECT** — TCP proxying (HTTP, HTTPS, SSH, etc.)
- **UDP ASSOCIATE** — UDP proxying (DNS, voice chats, games, etc.)

Address types: IPv4, IPv6, domain names. Domain resolution happens on the server side.

## Building

```bash
cargo build --release
```

Binary: `target/release/fiend` (single binary for server, client, and fingerprint modes).

## Thanks to

- [Xray-core](https://github.com/XTLS/Xray-core) and [utls](https://github.com/refraction-networking/utls) for inspiration.
