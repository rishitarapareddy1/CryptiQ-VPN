# CryptiQ edge peer

Local / staging edge node for CryptiQ Personal. Speaks the hybrid
ML-KEM-768 + X25519 handshake, then registers each client's WireGuard
public key and writes `wg-cryptiq.conf`.

## Run

```bash
# terminal 1 — edge
cargo run --manifest-path edge/Cargo.toml

# terminal 2 — optional: bring up the WireGuard interface (needs admin)
sudo wg-quick up ./edge/wg-cryptiq.conf

# then connect from CryptiQ Personal (edge URL default: http://127.0.0.1:8787)
```

## Protocol

1. `GET /v1/handshake/start` → ML-KEM public key, server X25519 public, server WireGuard public, endpoint
2. Client encapsulates, derives hybrid session key, generates WireGuard keypair
3. `POST /v1/handshake/finish` with ciphertext + client X25519 public + client WireGuard public
4. Edge verifies, assigns `10.66.66.N`, returns fingerprint + VPN IPs

The hybrid session key does two jobs. It authenticates steps 1–3 (so an
eavesdropper who records the handshake can't later recover the WireGuard peer
keys by breaking classical crypto alone), and it's fed into `derive_wg_psk`
to become the WireGuard PresharedKey both sides install. Because WireGuard
folds the PSK into every key it derives, the *data plane* — not just the
handshake — now also requires breaking ML-KEM-768 in addition to Curve25519.
WireGuard's own cipher (ChaCha20-Poly1305) is still classical, so this is
hybrid PQ hardening, not a full PQ AEAD replacement — but recorded traffic
can't be decrypted later by breaking Curve25519 alone.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `CRYPTIQ_EDGE_BIND` | `127.0.0.1:8787` | HTTP listen address |
| `CRYPTIQ_WG_ENDPOINT` | `127.0.0.1:51820` | Advertised WireGuard endpoint |
| `CRYPTIQ_EDGE_STATE_DIR` | `edge/` (crate dir) | Where the persistent server key + generated `wg-cryptiq.conf` live |
| `CRYPTIQ_EDGE_DNS` | `1.1.1.1` | Resolver pushed to clients (full-tunnel clients pin DNS here) |
| `CRYPTIQ_NAT_IFACE` | unset | Outbound interface (e.g. `eth0`). When set, the server config gets iptables MASQUERADE rules so full-tunnel clients reach the internet |

The server WireGuard key is generated once and persisted to
`$CRYPTIQ_EDGE_STATE_DIR/wg-server.key`, so restarts don't invalidate
client configs.

## Production deploy (Ubuntu VPS)

One public box gives every download user something real to connect to.
The `Dockerfile` here is a valid way to build/ship the binary, but the
production box (`64.181.224.148`) actually runs it as a bare binary under
systemd — no Docker daemon on that host. `edge/deploy/` has the exact unit
files in use; this is the path that's actually verified working end-to-end
(real handshake, real full-tunnel traffic, sustained megabytes transferred).

```bash
# 1. install wireguard + enable forwarding
sudo apt install -y wireguard-tools iptables-persistent
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-cryptiq.conf && sudo sysctl --system

# 2. build the binary on the box (no cross-compile toolchain assumed)
curl https://sh.rustup.rs -sSf | sh -s -- -y
# copy edge/ to the box (scp or git clone), then:
cd cryptiq-edge-src && cargo build --release

# 3. install the systemd units (adjust User=/paths/CRYPTIQ_WG_ENDPOINT/
#    CRYPTIQ_NAT_IFACE in cryptiq-edge.service to match your box first)
sudo cp edge/deploy/cryptiq-edge.service edge/deploy/cryptiq-wg-sync.service \
        edge/deploy/cryptiq-wg-sync.timer /etc/systemd/system/
sudo cp edge/deploy/cryptiq-wg-sync /usr/local/bin/cryptiq-wg-sync
sudo chmod +x /usr/local/bin/cryptiq-wg-sync
sudo systemctl daemon-reload
sudo systemctl enable --now cryptiq-edge.service cryptiq-wg-sync.timer

# 4. open ports 8787/tcp (handshake) and 51820/udp (WireGuard) in your firewall
```

Then point the app's Settings → Edge URL at `http://YOUR_IP:8787` (put a
TLS reverse proxy such as Caddy in front for production) and enable
"Route all traffic through the tunnel" for full-VPN mode.

### Two gotchas that cost real debugging time — check both on any new box

1. **`FORWARD` chain ordering.** Cloud images (confirmed on this exact
   Oracle box) often ship a catch-all `REJECT --reject-with
   icmp-host-prohibited` at the *end* of the `FORWARD` chain already.
   `rewrite_server_conf` in `edge/src/main.rs` writes its `PostUp` rules
   with `iptables -I FORWARD 1 ...` (insert at the top) specifically so
   they land ahead of that reject — an `-A` append would silently never
   fire. Verify with `sudo iptables -L FORWARD -n -v --line-numbers`: our
   two `ACCEPT` rules for the `wg-cryptiq` interface must come *before*
   any unconditional `REJECT`/`DROP`.

2. **`cryptiq-wg-sync` needs real root, not just a NOPASSWD user.**
   `cryptiq-edge.service` runs as an unprivileged user (`User=ubuntu`), and
   it calls `/usr/local/bin/cryptiq-wg-sync` directly — with no `sudo`
   wrapper — every time a peer registers, plus every 30s via
   `cryptiq-wg-sync.timer`. The script in `edge/deploy/cryptiq-wg-sync`
   therefore prefixes every privileged step with its own `sudo`, and uses
   a temp file instead of `<(process substitution)` — `sudo` closes
   inherited file descriptors by default, which breaks that pipe with a
   cryptic `fopen: No such file or directory`. Skip either fix and the
   *symptom* is brutal to trace back to this: `wg syncconf` replaces the
   entire peer table with whatever it reads, so a permission failure here
   doesn't just fail loudly — it silently re-syncs to a **stale** list
   every 30 seconds, evicting whichever peer just connected. That reads
   as "the tunnel works for ~10–30 seconds then the internet dies," which
   looks nothing like a permissions bug.

   This also requires the unprivileged user actually having root
   available via `sudo` — on Ubuntu cloud images that's typically a
   blanket `ubuntu ALL=(ALL) NOPASSWD:ALL` from cloud-init. That's broader
   than this script needs (it only ever runs `cp`, `wg-quick`, `wg`); if
   you're hardening this deployment, scope it to a dedicated
   `/etc/sudoers.d/cryptiq` rule restricted to those three commands
   instead of leaving the default wide open.
