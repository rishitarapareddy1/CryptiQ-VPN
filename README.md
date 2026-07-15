# CryptiQ Personal

Consumer quantum-safe protection for your laptop. Desktop app built with Tauri v2
(Rust backend + React frontend). Download it, scan every cryptographic asset on
the machine, and convert what's convertible — with review-and-approve gating and
one-click rollback.

## What works in this build

### Crypto
- **Hybrid post-quantum handshake** (`src-tauri/src/pqc.rs`) — real ML-KEM-768
  (FIPS 203) lattice key encapsulation combined with X25519 ECDH through a
  SHA-256 KDF. Both sides currently run in-process; the WireGuard transport to
  edge nodes is the remaining piece.

### Scanners (`src-tauri/src/scanner.rs`) — all read real machine state
- SSH keys in `~/.ssh` — algorithm + bit length (RSA/DSA/ECDSA flagged)
- SSH `known_hosts` — servers still presenting RSA/DSA host keys
- GPG keyring — RSA/DSA/ElGamal keys flagged (if gpg installed)
- FileVault disk-encryption status
- Current Wi-Fi network security mode (WPA3 / WPA2 / open)
- Login Keychain certificates with weak (<2048-bit) RSA keys
- macOS version / system TLS post-quantum support
- Git commit-signing configuration

### Migration engine (`src-tauri/src/migrate.rs`)
- **SSH migration** — generates an Ed25519 keypair at `~/.ssh/cryptiq_ed25519`
  and wires it into `~/.ssh/config` via a clearly-marked managed block. Original
  keys and config are never deleted.
- **Snapshots + rollback** — the exact pre-migration file content is stored in
  SQLite before any change; every applied migration has a working Roll back button.
- **Wi-Fi policy** — flag untrusted (WPA2/open) networks as tunnel-required.
- Applied state persists across app restarts.

### Transparency
- **Technical audit tab** — for every applied migration: the exact file changed
  with a before/after line diff (reconstructed from the stored snapshot), the
  generated key's fingerprint, and full handshake parameters (FIPS 203 sizes,
  KDF construction, ciphertext preview).
- **Manual findings carry fix instructions** — concrete steps shown inline for
  everything the app can't safely change itself (FileVault, GPG, vendor certs…).

### Distribution
- `website/download.html` — drop-in download page for the CryptiQ site (real
  SHA-256 checksum, first-launch instructions). Point the button at your CDN or
  a public GitHub release asset.
- Installer published at GitHub Releases (`gh release create vX.Y.Z <dmg>`).

### Product surface
- Onboarding flow on first launch
- Menu-bar tray icon (open / quit)
- State-driven UI: Exposed / Negotiating / Protected
- On-device SQLite at `~/Library/Application Support/CryptiQ Personal/cryptiq.db` —
  inventory, scan history, remediation log, snapshots, settings. Nothing leaves
  the device.

## Run it

```bash
npm install
npm run tauri dev      # development
npm run tauri build    # produces .app and .dmg installer
```

Requires Rust (`rustup`) and Node 18+.

## Tests

```bash
cd src-tauri && cargo test
```

12 integration tests: handshake correctness (incl. FIPS 203 ciphertext size),
SSH key classification against real `ssh-keygen`-generated keys, SQLite
round-trips, snapshot/rollback bookkeeping, and a live scan of the host machine.

## Not built yet

- WireGuard transport (needs Apple Network Extension entitlement + edge servers)
- Code signing + notarization (needs an Apple Developer account) — unsigned
  builds require right-click → Open on first launch
- Accounts / billing / cross-device sync (cloud Postgres side)
- Auto-update
