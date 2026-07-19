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

```bash
# 1. install wireguard + enable forwarding
sudo apt install -y wireguard-tools
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-cryptiq.conf && sudo sysctl --system

# 2. run the edge (docker)
docker build -f edge/Dockerfile -t cryptiq-edge .
docker run -d --name cryptiq-edge --restart unless-stopped \
  -p 8787:8787 -v /var/lib/cryptiq-edge:/state \
  -e CRYPTIQ_WG_ENDPOINT="$(curl -s ifconfig.me):51820" \
  -e CRYPTIQ_NAT_IFACE=eth0 \
  cryptiq-edge

# 3. bring up WireGuard on the host (re-run after new peers join,
#    or use `wg syncconf` in a small cron/systemd timer)
sudo wg-quick up /var/lib/cryptiq-edge/wg-cryptiq.conf

# 4. open ports 8787/tcp (handshake) and 51820/udp (WireGuard) in your firewall
```

Then point the app's Settings → Edge URL at `http://YOUR_IP:8787` (put a
TLS reverse proxy such as Caddy in front for production) and enable
"Route all traffic through the tunnel" for full-VPN mode.
