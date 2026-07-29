# Deployment — CHRONOS Agent

VDF and SNARK prover are stubbed; replace before a real mission.

---

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| Rust toolchain | `stable-x86_64-pc-windows-gnu` (Windows) or `stable-x86_64-unknown-linux-musl` (Linux) |
| GMP | ≥ 6.3 |
| CMake | ≥ 3.20 (required by `gmp-mpfr-sys` build script) |
| Linux capabilities | `CAP_IPC_LOCK` for `mlock()` — see §3 |

---

## Build

```bash
# Linux — fully static
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/chronos-agent
du -sh target/x86_64-unknown-linux-musl/release/chronos-agent
```

---

## OS capabilities

```bash
# Allow mlock without root
sudo setcap cap_ipc_lock+ep ./chronos-agent

# Disable core dumps (the agent checks this at startup)
ulimit -c 0
# systemd: LimitCORE=0, NoNewPrivileges=true
```

---

## certN.bin — MPC modulus

`certN.bin` must come from a real MPC ceremony (e.g. Diogenes). Until then, the agent will refuse to start if the file is missing.

**Dev only — not for real use:**
```bash
openssl genrsa -out /tmp/rsa.pem 2048
openssl rsa -in /tmp/rsa.pem -text -noout | grep "modulus:" -A 50 \
  | grep "    " | tr -d ' :\n' | xxd -r -p > certN.bin
chmod 600 certN.bin
```

**For deployment:** run Diogenes MPC with your committee. Export `N` as big-endian bytes → `certN.bin`, point `config.crypto.cert_n_path` at it.

---

## Config

```bash
cp crates/chronos-agent/config/default.toml config.toml
# Set cert_n_path, ct_sk_path, drand_url at minimum
chmod 600 config.toml
```

---

## Run

```bash
RUST_LOG=chronos=info ./chronos-agent --config config.toml
```

API: `127.0.0.1:8080` — Metrics: `127.0.0.1:9090`

Override via env: `CHRONOS__SERVER__API_ADDR=0.0.0.0:8080`

---

## systemd unit

```ini
[Unit]
Description=CHRONOS dead man's switch
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

1. `systemctl stop chronos` — SIGTERM; keys are zeroized on exit.
2. Revert commit, rebuild.
3. `systemctl start chronos`.

Once the mission reaches `Erased`, the agent exits 0. `certN.bin` and `ct_sk.bin` must be re-provisioned before a new run.

---

## Known gaps

| Gap | What's needed |
|-----|---------------|
| VDF proof is modular squaring only | Implement Pietrzak verifier |
| Groth16 circuit is a single trivial constraint | Wire real AES-GCM constraints |
| Drand BLS verification is hex length check only | `bls12_381` pairing |
| `certN.bin` is a placeholder | MPC ceremony |
