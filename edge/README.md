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

The PQ handshake is what makes the *control plane* quantum-safe: an eavesdropper
who records steps 1–3 cannot later recover the WireGuard peer keys by breaking
classical crypto alone. The WireGuard *data plane* still uses Curve25519
(standard today); migrating that to a PQ AEAD is a later protocol change.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `CRYPTIQ_EDGE_BIND` | `127.0.0.1:8787` | HTTP listen address |
| `CRYPTIQ_WG_ENDPOINT` | `127.0.0.1:51820` | Advertised WireGuard endpoint |
