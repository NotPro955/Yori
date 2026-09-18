# Security Notes

Yori is a security-focused academic prototype. It is not Signal, Tor, or a production anonymous communication system.

## Current protections

- X25519 is used for ephemeral key agreement.
- HKDF-SHA256 derives session material.
- Ed25519 identity keys sign ephemeral session data in memory.
- AES-256-GCM authenticates encrypted session and message content.
- Directional send and receive keys are derived separately.
- Message IDs, session IDs, counters, and duplicate-counter checks provide basic replay protection.
- Onion relay layers are encrypted independently for each relay.
- Relays open fresh TCP connections for each hop.
- Packet sizes, protocol versions, TTLs, and scanner buffers are bounded.

## Server knows

- Connected usernames and presence.
- Advertised peer addresses and relay public keys needed for rendezvous.
- Timing and approximate traffic volume.
- Final delivery requests and the final recipient required for delivery.

The server does not log encrypted payloads or session secrets in normal packet logs.

## Relay knows

- The connection immediately before it.
- Its own next-hop address from its onion layer.
- An opaque encrypted remainder.
- Timing and packet size.

## Recipient knows

- The authenticated sender identity carried inside the end-to-end encrypted message.
- The message contents after successful AES-GCM authentication.

## Limitations

- Direct peer TCP requires reachable advertised addresses. NAT, firewalls, and changing addresses can prevent delivery.
- A global observer can correlate timing, sizes, and connection patterns.
- The server can observe presence and final delivery metadata.
- Endpoint compromise, keyloggers, screenshots, malicious majority relays, and operating-system compromise are not prevented.
- The message counter design is not a Signal Double Ratchet and does not provide full asynchronous ratcheting.
- Identity keys are currently in-memory and are not persistent across client restarts.
- Cover traffic, sophisticated timing defenses, Tor integration, DHT behavior, and production NAT traversal are out of scope for V1.
