# CryptiQ Personal

Consumer quantum-safe protection for your laptop. Desktop app built with Tauri v2
(Rust backend + React frontend). Download it, scan every cryptographic asset on
the machine, and convert what's convertible — with review-and-approve gating and
one-click rollback.

## Download

**[CryptiQ Personal 0.7.0 (.dmg)](https://github.com/rishitarapareddy1/CryptiQ-VPN/releases/latest/download/CryptiQ-Personal-0.7.0.dmg)**

- macOS 12+ on **Apple Silicon** (the bundled WireGuard binaries are arm64 only).
- WireGuard ships inside the app — no Homebrew, no separate install.
- The build isn't notarized yet, so Gatekeeper will block the first launch:
  right-click the app → **Open** → **Open Anyway**.

The app points at the hosted CryptiQ edge (`http://64.181.224.148:8787`) by
default, so the tunnel works out of the box. You can change the edge URL in
Settings, including to a local one you run yourself (see below).

## What works in this build (0.7.0)

### Tunnel
- **Networked hybrid handshake** with a CryptiQ edge: ML-KEM-768 + X25519 over
  HTTP, then WireGuard peer exchange authenticated by the shared session key
  (`src-tauri/src/pqc.rs`, `src-tauri/src/tunnel.rs`).
- **PQ-hardened data plane.** The hybrid session key is domain-separated into a
  WireGuard `PresharedKey` (`derive_wg_psk`) that both sides install. WireGuard
  folds the PSK into every key it derives, so recorded traffic can't be
  decrypted later by breaking Curve25519 alone.
- **Full-device routing.** `AllowedIPs = 0.0.0.0/0, ::/0` with pinned DNS, or
  peer-only routing. Wi-Fi policy can force full-tunnel on untrusted networks.
- **Bundled WireGuard.** A packaged `.app` carries its own `wg`, `wg-quick`,
  `wireguard-go`, and a self-contained bash 4+, so the tunnel comes up on a
  machine with no Homebrew at all.
- Without admin rights you still get a valid config to import into the
  WireGuard app (`state=config_ready`), plus a retry that re-prompts for admin.
- **Edge peer** (`edge/`) — runs locally for development, or on a VPS under
  systemd for production. Assigns VPN IPs (`10.66.66.N`) and writes
  `wg-cryptiq.conf`. See [edge/README.md](edge/README.md).

### Crypto
- Real ML-KEM-768 (FIPS 203) lattice key encapsulation + X25519 through a
  SHA-256 hybrid KDF. Offline in-process handshake still available for tests.

### Scanners (`src-tauri/src/scanner.rs`) — all read real machine state
- SSH keys, `known_hosts`, GPG keyring, FileVault, Wi-Fi, Keychain certs,
  OS TLS stack, Git commit signing

### Migration engine (`src-tauri/src/migrate.rs`)
- SSH migration with a managed `~/.ssh/config` block
- Git commit-signing migration
- Wi-Fi force-tunnel policy
- Snapshots + one-click rollback for everything above

### Transparency
- Technical audit tab (before/after diffs, key fingerprints, handshake params)
- Manual findings with inline fix instructions

### Product surface
- Onboarding, tray icon, on-device SQLite, five tabs (Shield / Assets /
  Technical / Log / Settings), download page under `website/`

## Build from source

```bash
# terminal 1 — local edge (optional; the app defaults to the hosted edge)
cargo run --manifest-path edge/Cargo.toml

# terminal 2 — optional: bring up the edge WireGuard interface
sudo wg-quick up ./edge/wg-cryptiq.conf

# terminal 3 — app
npm install
npm run tauri dev
```

Then hit **Connect quantum-safe tunnel** on the Shield tab.

Requires Rust (`rustup`) and Node 18+.

One dev-only caveat: the bundled WireGuard is resolved relative to a packaged
`.app`, so under `npm run tauri dev` the app falls back to a system install. To
bring the interface up in a dev build you still need `brew install
wireguard-tools bash`. Users of the `.dmg` don't. `npm run tauri build`
produces the bundled, self-contained app.

## Tests

```bash
cd src-tauri && cargo test        # 22 tests, no running edge required
```

CLI harnesses that exercise the real code paths:

```bash
# scan this machine and print findings (read-only)
cargo run --example scan_and_migrate
# add --apply to run the real auto-migrations against your own machine
# (snapshotted and rollback-able, but it does change real config)

# live handshake against a running edge
CRYPTIQ_WG_DIR=/tmp/cryptiq-wg cargo run --example live_edge
```

## Honest limits

- WireGuard's cipher is still ChaCha20-Poly1305, which is classical. The PQ
  guarantee comes from the ML-KEM-derived PSK folded into key derivation — real
  harvest-now-decrypt-later protection, but not a full PQ AEAD replacement.
- The handshake runs over plain HTTP. The protocol authenticates itself with the
  hybrid session key, so this isn't as bad as it sounds, but there's no TLS.
- **The edge has no accounts, auth, or rate limiting.** Anyone who can reach it
  can request a peer slot.
- Builds are unsigned and un-notarized (Gatekeeper "Open Anyway").
- Apple Silicon macOS only — no Intel, Linux, or Windows build.
- Accounts / billing / notarization still ahead.
