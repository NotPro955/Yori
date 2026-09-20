# Protocol V1

## Transport

Browser clients connect to the server over WebSocket. The server coordinates presence and forwards opaque packets; it never terminates a chat session.

## Packet metadata

Packets contain `version`, random `id`, optional `circuit_id`, bounded `ttl`, `type`, destination where required, and an opaque payload.

Supported server-facing types include `users`, `deliver`, `heartbeat`, `waiting`, `message`, `session_offer`, and `session_reply`. Unknown or malformed packets are rejected.

## Discovery

A browser registers a username and an ephemeral relay public key. The server returns online peers and their relay public keys. It never returns identity keys, chat pre-session keys, private keys, or peer addresses.

## Sessions

Chat pre-session public keys are exchanged only through a trusted external channel. They are not registered with or returned by the server.

To establish a session, the initiator creates an ephemeral X25519 keypair and random session ID, signs its ephemeral public key and session ID with its Ed25519 identity, then seals that offer to the recipient's externally exchanged pre-session public key. The recipient decrypts it with its matching private pre-session key, verifies the signature, creates its own ephemeral X25519 keypair, and seals a signed reply to the initiator's ephemeral public key.

Both browsers derive the same ephemeral X25519 shared secret and use HKDF-SHA256 to derive distinct directional AES-256-GCM keys. An AES key is never sent over the network, encrypted or otherwise.

The server forwards opaque session packets and never receives the private or derived session keys.

## Onion routing

Relay public keys are a separate key class from chat pre-session keys. The server distributes relay public keys through peer discovery. When at least two relay peers are available, the sender selects two distinct relays, excluding sender and recipient. It encrypts each onion layer to the corresponding relay public key. A relay decrypts exactly one layer with its relay private key and forwards the encrypted remainder. The final relay sends a `deliver` packet to the server, which forwards the opaque payload to the named recipient.

## Messages

Messages are encrypted with AES-256-GCM. The authenticated envelope contains protocol version, session ID, random message ID, monotonic counter, sender label, and body. Session context is used as AEAD associated data. Duplicate counters are rejected.

## Limitations

This protocol is a prototype and does not implement a Double Ratchet, cover traffic, global timing protection, persistent verified identity storage, or production NAT traversal.
