# reprise-net

QUIC transport, ed25519 peer identity, and a typed request/response protocol
(bincode `Packet` envelope with command discriminants + layout fingerprints).

Shared by Strawberry and webhopper. Two crates:

- `reprise-net` — the transport + protocol.
- `reprise-net-derive` — the `Command`/`Layout`/`command_set!` proc-macros.

Extracted from the Strawberry repository (history preserved via `git subtree`).
