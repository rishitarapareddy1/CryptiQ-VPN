# CryptiQ Personal

Consumer quantum-safe protection for your laptop. Desktop app built with Tauri v2
(Rust backend + React frontend).

## What actually works in this build

- **Hybrid post-quantum handshake** — real ML-KEM-768 (FIPS 203) lattice key
  encapsulation combined with X25519 ECDH through a SHA-256 KDF, running in the
  Rust backend (`src-tauri/src/pqc.rs`). Both sides run in-process for now;
  wiring the derived keys into a WireGuard tunnel to an edge node is the next step.
- **Real asset scanners** (`src-tauri/src/scanner.rs`) — reads your actual machine:
  - `~/.ssh/*.pub` key algorithms and bit lengths (RSA/DSA/ECDSA flagged)
  - FileVault disk-encryption status (`fdesetup`)
  - macOS version / system TLS post-quantum support
  - Git commit-signing configuration
- **Real remediation** — queued SSH findings generate a fresh Ed25519 keypair at
  `~/.ssh/cryptiq_ed25519` (non-destructive; never touches existing keys).
- **On-device SQLite** (`src-tauri/src/store.rs`) — asset inventory, scan history,
  and remediation log at `~/Library/Application Support/CryptiQ Personal/cryptiq.db`.
  Nothing leaves the device.

## Run it

```bash
npm install
npm run tauri dev
```

Requires Rust (`rustup`) and Node 18+.

## Not built yet

- WireGuard transport (needs a Network Extension entitlement + edge servers)
- Rollback snapshots for applied migrations
- Accounts / billing / cross-device sync (cloud Postgres side)
- Menu-bar tray mini view, onboarding, auto-update, signing + notarization
