# Yori

Yori is a browser-based, security-focused chat prototype deployed as a public Render service. The Go server serves the web application and provides coordination, presence, and opaque packet delivery.

## Use Yori

1. Open `https://<your-yori-service>.onrender.com`.
2. Enter a username.
3. Select an online peer and connect.
4. Use Yori normally.

The browser derives its WebSocket endpoint from the page URL. A Render page therefore connects to `wss://<your-yori-service>.onrender.com/ws` automatically; users never need to enter an address.

## Deploy on Render

Render supplies the `PORT` environment variable. The server listens on `0.0.0.0:$PORT`; no additional server address configuration is required. When Render provides `RENDER_EXTERNAL_HOSTNAME`, the server prints its public URL during startup.

Build the server from the `server` directory:

```bash
go build -o yori-server .
```

Start command:

```bash
./yori-server
```

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
