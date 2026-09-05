# CHRONOS Ceremony Deployment Guide

This guide covers running a production multi-party ceremony and deploying the resulting keys.

## Table of Contents

- [Pre-ceremony checklist](#pre-ceremony-checklist)
- [Running the ceremony](#running-the-ceremony)
- [Post-ceremony verification](#post-ceremony-verification)
- [Deploying keys](#deploying-keys)
- [Troubleshooting](#troubleshooting)

---

## Pre-ceremony checklist

### Coordinator responsibilities

- [ ] **Set ceremony parameters**
  - Determine number of powers (recommend 16384 for CHRONOS erasure circuit)
  - Set Phase 1 and Phase 2 participant counts (recommend ≥5 and ≥3)
  - Establish contribution deadlines (recommend 48 hours per participant)

- [ ] **Recruit participants**
  - Identify participants from independent organizations/countries
  - Confirm each participant has Rust toolchain installed
  - Distribute the CEREMONY.md participation guide
  - Establish secure communication channels (Signal, PGP email, etc.)

- [ ] **Prepare infrastructure**
  - Set up file transfer mechanism (HTTPS upload, SFTP, encrypted email)
  - Prepare public announcement channel (website, Twitter, GitHub)
  - Configure backup storage for intermediate states

- [ ] **Document ceremony plan**
  - List participants in contribution order
  - Set start date and expected completion date
  - Define escalation procedure if a participant ghosts

### Participant responsibilities

- [ ] **Verify environment**
  - Rust toolchain installed (`rustup --version`)
  - CHRONOS repository cloned and builds successfully
  - Secure machine available (preferably air-gapped or freshly installed VM)

- [ ] **Understand security requirements**
  - Read CEREMONY.md security model section
  - Plan for secret destruction (reboot machine or destroy VM after contributing)
  - Prepare verification procedure for next participant's contribution

---

## Running the ceremony

### Phase 1: Powers of Tau

#### Step 1: Coordinator initializes

```sh
cargo run --example ceremony_cli -- init \
    --powers 16384 \
    --output ceremony_phase1_init.json
```

**Output**: `ceremony_phase1_init.json`

Publish this file and its challenge hash on the public announcement channel:

```sh
cargo run --example ceremony_cli -- status \
    --input ceremony_phase1_init.json
```

Copy the "Current challenge hash" and post it publicly.

#### Step 2: First participant contributes

Participant receives `ceremony_phase1_init.json` and verifies the challenge hash matches the public announcement.

```sh
# Verify challenge hash
cargo run --example ceremony_cli -- status \
    --input ceremony_phase1_init.json

# Contribute
cargo run --example ceremony_cli -- contribute \
    --input ceremony_phase1_init.json \
    --contributor "Alice (Acme Corp)" \
    --output ceremony_after_alice.json

# Reboot or destroy VM to erase secret τ
sudo reboot
```

Participant sends `ceremony_after_alice.json` to coordinator and posts their contribution's challenge hash publicly.

#### Step 3: Coordinator verifies and advances

```sh
# Verify Alice's contribution
cargo run --example ceremony_cli -- verify \
    --before ceremony_phase1_init.json \
    --after ceremony_after_alice.json

# If verification passes, this becomes the new canonical state
cp ceremony_after_alice.json ceremony_phase1_current.json

# Publish new challenge
cargo run --example ceremony_cli -- status \
    --input ceremony_phase1_current.json
```

Post the new challenge hash publicly and send the file to the next participant.

#### Step 4: Repeat for all Phase 1 participants

For each participant (Bob, Charlie, ...):

1. Coordinator sends current state file
2. Participant verifies challenge hash publicly
3. Participant contributes and destroys their secret
4. Participant sends contribution back and posts new hash
5. Coordinator verifies, updates canonical state, publishes new hash
6. **Previous participant verifies** the new contribution was computed correctly from theirs

Continue until all Phase 1 participants have contributed.

**Typical timeline**: 5 participants over 5–10 days.

#### Step 5: Transition to Phase 2

After the last Phase 1 contribution:

```sh
cargo run --example ceremony_cli -- transition \
    --input ceremony_phase1_final.json \
    --output ceremony_phase2_init.json
```

Publish Phase 2 genesis state and announce Phase 2 participant call.

### Phase 2: Circuit-specific

Phase 2 follows the same pattern as Phase 1:

1. Coordinator sends challenge to first Phase 2 participant
2. Participant contributes and destroys secret
3. Coordinator verifies and advances
4. Repeat for all Phase 2 participants

Phase 2 is faster (~2 seconds per contribution vs ~60 seconds for Phase 1).

**Typical timeline**: 3 participants over 3–5 days.

### Finalization

After the last Phase 2 contribution:

```sh
cargo run --example ceremony_cli -- finalize \
    --input ceremony_phase2_final.json \
    --proving-key chronos_ceremony_2027.pk \
    --verifying-key chronos_ceremony_2027.vk
```

**Output**:
- `chronos_ceremony_2027.pk` (~1.5 MB)
- `chronos_ceremony_2027.vk` (~1.5 KB)

These are the **deployment keys**.

---

## Post-ceremony verification

### Coordinator publishes artifacts

Upload to a permanent, public location (GitHub release, IPFS, etc.):

1. **Final transcript**: `ceremony_phase2_final.json`
2. **Verifying key**: `chronos_ceremony_2027.vk`
3. **Transcript summary**: List of all participants, contribution hashes, timeline

**Do NOT publish the proving key publicly** — it's large and only needed by CHRONOS agents.

### External auditors verify

Given the published transcript and verifying key, auditors should:

#### 1. Verify the challenge chain

```sh
# For each contribution in the transcript:
cargo run --example ceremony_cli -- verify \
    --before ceremony_state_N.json \
    --after ceremony_state_N_plus_1.json
```

All verifications must pass. If any fail, the ceremony is invalid.

#### 2. Recompute the verifying key

```sh
# Rebuild ceremony_cli from source (trust the code, not binaries)
cargo build --example ceremony_cli --release

# Replay the ceremony with the published transcript
# (Full replay requires contribution files, not just final state)
# This confirms the verifying key matches the transcript.
```

#### 3. Check participant diversity

- Are participants from independent organizations?
- Are they geographically distributed?
- Did any participant verify the next one's contribution?

If ≥1 participant is credibly honest, the setup is secure.

---

## Deploying keys

### Update CHRONOS prover

Add ceremony keys to the agent's deployment:

```rust
use chronos_snark::prover::Groth16Prover;

// Load ceremony-generated keys
let transcript_head = [0xAB, 0xCD, 0xEF, /* ... final challenge hash ... */];
let prover = Groth16Prover::load_ceremony_keys(
    "chronos_ceremony_2027.pk",
    "chronos_ceremony_2027.vk",
    transcript_head,
)?;

// Use for proof generation
let proof = prover.prove_erasure(&witness)?;
```

The `transcript_head` is the final Phase 2 challenge hash from the ceremony. This binds the prover to a specific ceremony run.

### Deploy verifying key on-chain

Export the verifying key to Solidity format:

```sh
cargo run --example export_solidity > Groth16Verifier_ceremony_2027.sol
```

Deploy the generated contract to your target EVM chain. Update any front-end or verification services to use the new contract address.

### Announce deployment

Post a public announcement:

- **Ceremony participants**: List all contributors by name/pseudonym
- **Transcript location**: Link to `ceremony_phase2_final.json`
- **Verifying key**: Link to `chronos_ceremony_2027.vk` and on-chain contract
- **Deployment date**: When the keys went live
- **Agent version**: Which CHRONOS release includes these keys

### Rotate keys (optional, future)

For a later ceremony (e.g., after a circuit change):

1. Run a new ceremony with a different set of participants
2. Generate new keys with a different filename (e.g., `chronos_ceremony_2028.pk`)
3. Deploy agents with both old and new keys, accepting proofs from either
4. After a transition period, deprecate old keys

---

## Troubleshooting

### Verification fails

**Symptom**: `cargo run --example ceremony_cli -- verify` returns an error.

**Causes**:
- **Tampered contribution**: A participant altered the file or copied an old state.
- **Wrong parent**: The contribution file is from a different ceremony or phase.
- **Corrupted transfer**: File was truncated or modified during transmission.

**Resolution**:
1. Reject the contribution
2. Contact the participant for clarification
3. Re-send the previous state and ask them to retry
4. If tampering is suspected, skip that participant and move to the next

### Participant ghosts

**Symptom**: Participant receives challenge but doesn't respond by deadline.

**Resolution**:
1. Contact participant via secondary channel (phone, Signal)
2. If no response after 48 hours, skip them
3. Send challenge to next participant in queue
4. Document the skip in the public transcript

### File transfer fails

**Symptom**: Contribution files are too large for email or get corrupted.

**Resolution**:
- Use a file transfer service that supports large files (Dropbox, Google Drive, SFTP)
- Verify file integrity with SHA-256 checksum after transfer:
  ```sh
  sha256sum ceremony_after_alice.json
  ```
- Compare checksums before and after transfer

### Challenge hash mismatch

**Symptom**: Participant's locally computed challenge hash doesn't match the public announcement.

**Causes**:
- Participant received a stale or wrong file
- Coordinator posted the wrong hash
- File was altered in transit

**Resolution**:
1. Coordinator re-sends the file via a different channel
2. Coordinator verifies their own copy's hash matches what they published
3. Participant re-downloads and re-verifies

### Proof fails after deployment

**Symptom**: Proofs generated with ceremony keys don't verify.

**Causes**:
- Proving key and verifying key are from different ceremonies
- Circuit changed between ceremony and deployment
- Proof serialization issue

**Diagnostics**:
```rust
// Check that PK and VK match
let mut pk_vk_bytes = Vec::new();
prover.verifying_key()?.serialize_compressed(&mut pk_vk_bytes)?;

let vk_bytes = std::fs::read("chronos_ceremony_2027.vk")?;
assert_eq!(pk_vk_bytes, vk_bytes, "PK and VK must match");
```

**Resolution**:
- Re-run `finalize` command from the same transcript
- Verify no circuit changes were made post-ceremony
- Check that both agent and verifier are using the same verifying key

---

## Ceremony metrics (reference)

From a test run with 5 Phase 1 and 3 Phase 2 participants:

| Metric | Value |
|--------|-------|
| Phase 1 duration | 7 days (including participant coordination) |
| Phase 2 duration | 3 days |
| Total wall-clock time | 10 days |
| Phase 1 contribution time (per participant) | ~60 seconds |
| Phase 2 contribution time (per participant) | ~2 seconds |
| Verification time (per contribution) | ~800 ms (Phase 1), ~50 ms (Phase 2) |
| Final transcript size | ~1.8 MB |
| Proving key size | ~1.5 MB |
| Verifying key size | ~1.5 KB |

---

## Support

Questions during ceremony deployment? Contact:

- **GitHub Issues**: [github.com/ChronosResearch/project-chronos/issues](https://github.com/ChronosResearch/project-chronos/issues)
- **Email**: [ceremony coordinator contact]
- **ORCID**: 0009-0001-7379-955X

---

## License

This deployment guide is part of CHRONOS and licensed under AGPL-3.0. See `LICENSE` in the repository root.
