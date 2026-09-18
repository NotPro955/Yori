# Protocol V1

## Transport

Connections use newline-delimited JSON with a maximum packet size. Client and server apply read/write deadlines. Direct relay connections carry a short registration line followed by one onion packet.

## Packet metadata

Packets contain `version`, random `id`, optional `circuit_id`, bounded `ttl`, `type`, destination where required, and an opaque payload.

Supported server-facing types include `users`, `deliver`, `heartbeat`, `waiting`, `message`, `session_offer`, and `session_reply`. Unknown or malformed packets are rejected.

## Discovery

A client registers a username, direct listener address, relay public key, and identity public key. The server returns up to three peer records. Peer addresses are necessary for direct TCP routing and are therefore a documented privacy tradeoff.

## Sessions

Clients generate ephemeral X25519 keys and a random session ID. The ephemeral public key and session ID are signed with an in-memory Ed25519 identity key. Both sides derive the same transport secret with X25519 and HKDF-SHA256, then derive separate directional keys.

The server forwards opaque session packets and never receives the private or derived session keys.

## Onion routing

The sender selects two to five distinct relays, excluding sender and recipient. Each layer contains only the next hop and an encrypted remainder. The relay decrypts exactly one layer, decrements TTL, applies bounded jitter, and opens a new TCP connection to the next hop. The final relay sends a `deliver` packet to the server, which forwards the opaque payload to the named recipient.

## Messages

Messages are encrypted with AES-256-GCM. The authenticated envelope contains protocol version, session ID, random message ID, monotonic counter, sender label, and body. Session context is used as AEAD associated data. Duplicate counters are rejected.

## Limitations

This protocol is a prototype and does not implement a Double Ratchet, cover traffic, global timing protection, persistent verified identity storage, or production NAT traversal.
