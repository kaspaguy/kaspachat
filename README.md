# Kaspaveil and KaspaChat

Kaspaveil is an end-to-end encrypted messaging protocol on Kaspa L1 that hides who talks to whom as well as what is said. KaspaChat is the app. Built by Kaspaguy (Thanaaya Technologies). Everything here is free software under AGPL-3.0 with attribution (see `LICENSE` and `NOTICE`).

**Status:** testnet-10. Nothing is on mainnet yet.

## What is here

| Folder | What it is |
|---|---|
| `protocol/` | The encryption and message format (TypeScript reference): hybrid post-quantum key exchange (ML-KEM-768 + X25519), double ratchet, padding, one-time tags, the 30-hour deletion, the device vault. Test vectors in `protocol/vectors/`. |
| `rust-impl/` | A second, independent implementation written from the spec. |
| `contracts/` | The Silverscript covenants: username registry, payment, reservoir and treasury, with their tests. |
| `app/`, `desktop/`, `mobile/`, `android-native/` | The web app, the Tauri desktop app, the Capacitor shell and the native Android app. |
| `relay/`, `indexer/`, `bouncer/`, `swaprelay/` | The servers: relay and doorman, indexer, name policy, swap quotes. Anyone can run their own. |
| `registry/` | The reserved-name list and the script that rebuilds it. |
| `tools/` | Chain daemon, testnet client, root-key ceremony tool, build scripts, `test-all.sh`. |
| `docs/` | Protocol specification, wire format, spec changelog, threat model. |

## Check it yourself

`tools/test-all.sh` runs every suite and the reproducibility checks (needs Node 22.18+, Rust, Python 3, MongoDB, and the Silverscript debugger; the header of the script says how).

What the code lets you check, and what it doesn't, is written down in `docs/THREAT_MODEL.md`.

## Security

Report problems privately: see `SECURITY.md`.
