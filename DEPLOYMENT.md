# Deployment — CHRONOS Agent

---

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| Rust toolchain | `stable` (1.97+) |
| Linux capabilities | `CAP_IPC_LOCK` for `mlock()` — see §OS Capabilities |
| `ct_sk.bin` | AES-256-GCM encrypted secret key (nonce 12B \|\| ciphertext+tag) |
| `certN.bin` | RSA modulus from MPC ceremony (big-endian bytes) — optional, falls back to RSA-2048 |

---

## Build

```bash
# Linux — fully static
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/chronos-agent

# Dev build
cargo build
cargo test
```

---

## OS Capabilities

```bash
# Allow mlock without root
sudo setcap cap_ipc_lock+ep ./chronos-agent

# Disable core dumps (agent checks this at startup and refuses to run if non-zero)
ulimit -c 0
```

---

## Provisioning `ct_sk.bin`

`ct_sk.bin` must be an AES-256-GCM ciphertext of the secret key, encrypted under
`K_enc = HKDF-SHA256(IKM=y, salt=drand_randomness)` where `y = g^(2^T) mod N`.

Layout: `nonce (12 bytes) || ciphertext || tag (16 bytes)`

For development/testing, the agent falls back to treating `ct_sk.bin` as a raw
key if AES-GCM decryption fails (logged as a warning). Remove this fallback for
production by deleting the `Err(e)` branch in `init_handler`.

```bash
chmod 600 ct_sk.bin
```

---

## Provisioning `certN.bin`

`certN.bin` is the RSA modulus `N` (big-endian bytes) used as the VDF group order.

**Production:** run a Diogenes MPC ceremony. Export `N` as big-endian bytes → `certN.bin`.

**Development:** if `certN.bin` is absent, the agent automatically falls back to the
hardcoded RSA-2048 challenge modulus (unfactored as of 2024) and logs a warning.
This is sufficient for testing but must not be used in production.

```bash
# Generate a dev modulus (not for production)
openssl genrsa -out /tmp/rsa.pem 2048
openssl rsa -in /tmp/rsa.pem -text -noout \
  | grep -A 50 "modulus:" | grep "    " \
  | tr -d ' :\n' | xxd -r -p > certN.bin
chmod 600 certN.bin
```

---

## Config

```bash
cp crates/chronos-agent/config/default.toml config.toml
# Edit: cert_n_path, ct_sk_path, drand_url, mission_id
chmod 600 config.toml
```

Key config fields:

```toml
[mission]
t_seconds   = 3600        # mission wall-clock timeout
t_vdf_steps = 1_000_000   # VDF squaring steps (determines time-lock strength)
mission_id  = "my-mission-001"

[crypto]
cert_n_path = "certN.bin"
ct_sk_path  = "ct_sk.bin"

[network]
drand_url          = "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest"
drand_timeout_secs = 10
```

---

## Run

```bash
RUST_LOG=chronos=info ./chronos-agent
```

- API: `127.0.0.1:8080`
- Metrics: `127.0.0.1:9090`

Override via env: `CHRONOS__SERVER__API_ADDR=0.0.0.0:8080`

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/status` | Current agent state (Armed/Active/Locked/Erased) |
| `POST` | `/mission/init` | Start mission — triggers VDF, FHE keygen, EAIP init |
| `POST` | `/infer` | FHE inference on submitted ciphertext |
| `POST` | `/verify` | Verify a Groth16 erasure proof (rate-limited) |
| `GET` | `/identity/proof` | Return ZK identity proof + ML-DSA signature |
| `GET` | `/metrics` | Prometheus metrics (port 9090) |

All endpoints require `X-Chronos-Nonce: <24 hex chars>` header for replay protection.

---

## Benchmarks

```bash
cargo run -p chronos-bench --release
```

---

## systemd Unit

```ini
[Unit]
Description=CHRONOS dead man's switch agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/chronos/chronos-agent
WorkingDirectory=/opt/chronos
EnvironmentFile=/opt/chronos/env
LimitCORE=0
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Prometheus

```yaml
scrape_configs:
  - job_name: chronos
    static_configs:
      - targets: ['127.0.0.1:9090']
```

---

## Rollback

1. `systemctl stop chronos` — SIGTERM triggers graceful shutdown; all secrets zeroized.
2. Revert commit, rebuild, `systemctl start chronos`.
3. Once `Erased`, the agent exits 0. Re-provision `certN.bin` and `ct_sk.bin` before a new run.

---

## Known Gaps

| Gap | Impact | What's needed |
|-----|--------|---------------|
| FHE evaluation is byte-reversal stub | Inference not cryptographically sound | Real TFHE-rs circuit |
| Groth16 AES-GCM gadget simulates constraints | Proof not binding to actual computation | Real AES-GCM R1CS gadget |
| MPC ceremony is simulated (3-party local) | Toxic waste not distributed | Real Powers-of-Tau ceremony |
| mTLS not enforced by axum | Plain HTTP in default config | Wire `rustls` acceptor |
