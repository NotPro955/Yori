# Threat Model

## Scope

Yori is a terminal P2P chat prototype with a central coordination/final-delivery server and direct TCP relay peers.

## Attackers

### Passive network observer

Can observe connections, timing, packet sizes, and peer addresses. Cannot decrypt authenticated AES-GCM payloads without endpoint/session keys.

### Malicious server

Can observe registrations, presence, advertised peer addresses, final delivery requests, timing, and traffic volume. It should not receive private keys, session secrets, or message plaintext.

### Malicious relay

Can observe its incoming connection, its own decrypted onion layer, its next hop, timing, and opaque encrypted payload. It cannot decrypt the end-to-end chat body without the endpoint session key.

### Malicious client

Can send malformed, oversized, replayed, or invalid packets. Packet validation, size limits, deadlines, AEAD, IDs, TTL, and duplicate checks reduce impact.

### Global observer

Can correlate traffic timing and sizes across the network. V1 does not provide global traffic-analysis resistance.

## Security goals

- Protect message contents from the server and intermediate relays.
- Detect modified encrypted messages and onion layers.
- Provide bounded, finite relay routes.
- Authenticate ephemeral session material with Ed25519 identity signatures.
- Reject duplicate message counters within a session.

## Non-goals

- Perfect anonymity.
- Protection from global traffic analysis.
- Tor compatibility or a Tor-like anonymity set.
- Full Signal Double Ratchet.
- Production NAT traversal or mobile/offline delivery.
