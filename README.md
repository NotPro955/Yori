# Yori

Yori is a browser-based, security-focused chat prototype. The Go server serves the web application and provides coordination, presence, and opaque packet delivery.

## Use Yori

1. Start the server.
2. Open its address in a browser.
3. Enter a username.
4. Select an online peer and connect.
5. Use Yori normally.

The browser derives its WebSocket endpoint from the page URL, so it uses `ws://` during local HTTP development and `wss://` when served over HTTPS.

## Run locally

```bash
go run .
```

## Exchange session keys externally

The server receives only usernames and opaque delivery packets; it never receives or lists browser session public keys. Each user must use **Share session key** to transmit their key through a trusted external channel, then use **Set Key** beside the corresponding online user to paste it locally.

Yori uses that externally exchanged key only to encrypt the session offer. The two clients then exchange fresh session public keys within the encrypted offer/reply and derive their chat keys locally. Relay public keys are separate, ephemeral routing keys advertised by the server as part of peer discovery. When two relay peers are available, messages use a multi-hop route; otherwise the server relays the same end-to-end encrypted envelope directly without receiving plaintext or session keys.

## Verification

Run from `server`:

```bash
go test ./...
go test -race ./...
go vet ./...
go build -o yori-server .
go mod tidy
```

## Security and limitations

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [PROTOCOL.md](PROTOCOL.md). This prototype does not claim perfect anonymity, global traffic-analysis resistance, Tor compatibility, production NAT traversal, or a Signal-equivalent ratchet.
