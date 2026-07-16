# CryptiQ Personal

Consumer quantum-safe protection for your laptop. Desktop app built with Tauri v2
(Rust backend + React frontend). Download it, scan every cryptographic asset on
the machine, and convert what's convertible — with review-and-approve gating and
one-click rollback.

## What works in this build

### Tunnel (v0.4)
- **Networked hybrid handshake** with a CryptiQ edge: ML-KEM-768 + X25519 over
  HTTP, then WireGuard peer exchange authenticated by the shared session key
  (`src-tauri/src/pqc.rs`, `src-tauri/src/tunnel.rs`).
- **Local edge peer** (`edge/`) — run with `cargo run --manifest-path edge/Cargo.toml`.
  Assigns VPN IPs (`10.66.66.N`) and writes `edge/wg-cryptiq.conf`.
- Client writes a WireGuard config after a successful handshake and attempts
  `wg-quick up`. Without admin rights you still get a valid config to import
  into the WireGuard app (`state=config_ready`).
- Shield button talks to the edge URL from Settings (default `http://127.0.0.1:8787`).

### Crypto
- Real ML-KEM-768 (FIPS 203) lattice key encapsulation + X25519 through a
  SHA-256 hybrid KDF. Offline in-process handshake still available for tests.

### Scanners (`src-tauri/src/scanner.rs`) — all read real machine state
- SSH keys, `known_hosts`, GPG keyring, FileVault, Wi-Fi, Keychain certs,
  OS TLS stack, Git commit signing

### Migration engine (`src-tauri/src/migrate.rs`)
- SSH migration with managed `~/.ssh/config` block, snapshots + rollback,
  Wi-Fi force-tunnel policy

### Transparency
- Technical audit tab (before/after diffs, key fingerprints, handshake params)
- Manual findings with inline fix instructions

### Product surface
- Onboarding, tray icon, on-device SQLite, download page under `website/`

## Run it

```bash
# terminal 1 — local edge
cargo run --manifest-path edge/Cargo.toml

# terminal 2 — optional: bring up the edge WireGuard interface
sudo wg-quick up ./edge/wg-cryptiq.conf

# terminal 3 — app
npm install
npm run tauri dev
```

Then hit **Connect quantum-safe tunnel** on the Shield tab.

Requires Rust (`rustup`), Node 18+, and (for the interface) `brew install wireguard-tools`.

## Tests

```bash
cd src-tauri && cargo test
# live against a running edge:
CRYPTIQ_WG_DIR=/tmp/cryptiq-wg cargo run --example live_edge
```

## Honest limits

- WireGuard *data plane* is still classical Curve25519 (industry standard). The
  PQ layer protects the *control plane* (how peers learn each other's keys).
- Full-device traffic routing (`AllowedIPs = 0.0.0.0/0`) and a production edge
  fleet are not in this build — local edge is for development.
- Bringing the interface up on macOS needs admin / the WireGuard app; unsigned
  builds still need Gatekeeper "Open Anyway".
- Accounts / billing / notarization still ahead.
