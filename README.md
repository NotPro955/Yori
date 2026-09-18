# Yori

Yori is a terminal-only, security-focused academic P2P chat prototype written in Go.

## Layout

- `client/` is an independent Go module for the terminal client.
- `server/` is an independent Go module for coordination, presence, and final delivery.
- `go.work` describes both modules, but the repository root contains no Go package. Run build/test commands inside each module.

## Run

Start the server:

```bash
cd server
go run .
```

Start multiple clients in separate terminals:

```bash
cd client
go run .
```

Clients need directly reachable peer listener addresses. Localhost works for same-machine testing; LAN or internet use requires suitable firewall/NAT configuration.

## Client flow

1. Connect clients with unique usernames.
2. Use `/users` to inspect discovered peers.
3. Exchange public session keys out of band.
4. Start a session with `/session <user> <public-key>`.
5. Chat with `/chat <user>`.
6. Use `/fingerprint <user>` to inspect the discovered identity fingerprint.
7. Use `/back` to leave chat and `/quit` to exit.

## Verification

Run from each module:

```bash
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

## Security and limitations

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [PROTOCOL.md](PROTOCOL.md). This prototype does not claim perfect anonymity, global traffic-analysis resistance, Tor compatibility, production NAT traversal, or a Signal-equivalent ratchet.
