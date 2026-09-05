# CHRONOS Multi-Party Ceremony Guide

This document explains how to participate in or coordinate a CHRONOS trusted setup ceremony for the Groth16 erasure proof system.

## Table of Contents

- [What is this ceremony?](#what-is-this-ceremony)
- [Why it matters](#why-it-matters)
- [Security model](#security-model)
- [Participant guide](#participant-guide)
- [Coordinator guide](#coordinator-guide)
- [Verification](#verification)
- [Technical details](#technical-details)

---

## What is this ceremony?

A **multi-party ceremony** (MPC) for generating Groth16 proving and verifying keys in a way that distributes trust across multiple participants. The ceremony has two phases:

1. **Phase 1 (Powers of Tau)**: Participants contribute randomness to build a structured reference string (SRS) that can be reused for circuits up to a fixed size.

2. **Phase 2 (Circuit-specific)**: Participants bind the Phase 1 output to the CHRONOS erasure circuit's constraint system.

After both phases complete, the coordinator extracts a **proving key** (used by agents to generate erasure proofs) and a **verifying key** (published so anyone can check the proofs).

---

## Why it matters

Groth16 requires a **trusted setup**: whoever samples the setup randomness learns a trapdoor that lets them forge proofs for any statement. A single-party setup means one person holds that power. A multi-party ceremony distributes it: the trapdoor can only be recovered if **every participant colludes**. If even one participant is honest (generates uniform randomness and destroys it), the setup is secure.

**CHRONOS v3 and earlier used a single-party setup.** This ceremony replaces it.

---

## Security model

### Assumptions

- **Discrete log is hard** in the BN254 elliptic curve groups 𝔾₁ and 𝔾₂.
- Each participant's machine samples **unbiased randomness** from the OS entropy source.
- Honest participants **destroy their secret** (τᵢ) after contributing and before publishing the contribution.

### Guarantees

- If **≥ 1 participant** is honest (uniform τᵢ, destroyed after use, verified the previous contribution), the final SRS is secure: no coalition of n−1 participants can recover the combined secret τ.
- Each contribution includes a **proof of knowledge**, so the coordinator and auditors can verify that the participant actually applied a secret exponent rather than copying the challenge forward unchanged.
- The ceremony transcript is **tamper-evident**: contributions are hash-chained, so reordering or altering past contributions is detectable.

### What this does NOT prevent

- A participant who contributes correctly, then later **leaks their τᵢ to an adversary** who also obtains every other secret. The security claim is "one honest destroys," not "n-of-n threshold secret sharing."
- **Side-channel attacks** on the participant's machine during contribution (e.g., memory snapshots, hardware keyloggers). Participants should run the contribution binary on a trusted, isolated machine.

---

## Participant guide

### Prerequisites

- Rust toolchain installed (`rustup` from rust-lang.org).
- The CHRONOS repository cloned locally.
- A **challenge file** from the coordinator (JSON format, e.g., `ceremony_state.json`).

### Step 1: Verify you have the correct challenge

```sh
cargo run --example ceremony_cli -- status --input ceremony_state.json
```

This prints the current phase, number of prior contributors, and the challenge hash. **Confirm the challenge hash with the coordinator** via a second channel (e.g., phone call, Signal) to ensure you're contributing to the correct ceremony.

### Step 2: Contribute

```sh
cargo run --example ceremony_cli -- contribute \
    --input ceremony_state.json \
    --contributor "Your Name" \
    --output ceremony_after_yourname.json
```

**What happens:**
1. The CLI samples 32 bytes of entropy from your OS's secure RNG.
2. It exponentiates the challenge parameters by your secret τ.
3. It generates a proof of knowledge that you applied a secret exponent.
4. It saves the updated parameters to the output file.

**Time:** Phase 1 contribution takes ~10–60 seconds depending on the number of powers. Phase 2 is faster (~1–5 seconds).

### Step 3: Self-verification

The CLI automatically verifies your contribution before saving. If this check fails, the contribution is rejected and an error is printed. **Do not proceed if verification fails.**

### Step 4: Publish your contribution

Send `ceremony_after_yourname.json` back to the coordinator via your agreed channel (email, secure file drop, etc.).

### Step 5: Destroy your secret

The secret τ is held in memory during contribution, then dropped when the process exits. Rust does not guarantee zeroization of stack-allocated values, so for maximum assurance:

- **Reboot your machine** after contributing, or
- Run the contribution binary inside a disposable VM that you destroy afterward.

This step is what makes you an **honest participant**. If you skip it and later leak your secret (even accidentally), you undermine the ceremony's security.

### Step 6: Verify the next contribution

Once the next participant's contribution is published, you should verify that it was computed correctly from yours:

```sh
cargo run --example ceremony_cli -- verify \
    --before ceremony_after_yourname.json \
    --after ceremony_after_nextperson.json
```

If verification fails, alert the coordinator immediately. A failed verification means the next participant either tampered with the state or submitted invalid cryptographic proofs.

---

## Coordinator guide

The **coordinator** sequences contributions, verifies each one, and maintains the canonical transcript.

### Step 1: Initialize the ceremony

```sh
cargo run --example ceremony_cli -- init --powers 16384 --output ceremony_phase1_init.json
```

**Powers:** Must be at least as large as the circuit's R1CS constraint count. For the CHRONOS erasure circuit (~8200 constraints), 16384 is safe. Larger values support bigger circuits but make contributions slower.

This creates the **genesis state**: Phase 1, contribution index 0, identity accumulator (τ = 1).

### Step 2: Publish the challenge

Send `ceremony_phase1_init.json` to the first participant. Also publish the **challenge hash** (printed by the `status` command) on a public channel (website, Twitter, Signal) so participants can verify they have the correct file.

### Step 3: Collect and verify each contribution

For each participant:

1. Receive their contribution file (`ceremony_after_alice.json`, `ceremony_after_bob.json`, etc.).
2. Verify it against the previous state:

   ```sh
   cargo run --example ceremony_cli -- verify \
       --before ceremony_phase1_init.json \
       --after ceremony_after_alice.json
   ```

3. If verification **passes**, this file becomes the new canonical state. Update the challenge:

   ```sh
   cp ceremony_after_alice.json ceremony_phase1_current.json
   ```

4. Publish the updated state and its challenge hash to the next participant.

If verification **fails**, **do not accept the contribution**. Contact the participant to understand what happened, and re-send them the last valid state.

### Step 4: Transition to Phase 2

After all Phase 1 participants have contributed (typically 3–10 is sufficient):

```sh
cargo run --example ceremony_cli -- transition \
    --input ceremony_phase1_current.json \
    --output ceremony_phase2_init.json
```

This produces the Phase 2 genesis state. Phase 2 contributions follow the same pattern as Phase 1.

### Step 5: Finalize and extract keys

After Phase 2 contributions complete:

```sh
cargo run --example ceremony_cli -- finalize \
    --input ceremony_phase2_current.json \
    --proving-key chronos.pk \
    --verifying-key chronos.vk
```

**Note:** The current implementation acknowledges ceremony completion but does not yet perform full Groth16 key derivation from the Phase 2 parameters. This is the next step in making the ceremony production-ready.

### Step 6: Publish the transcript

The final `ceremony_phase2_current.json` is the **auditable transcript**. Publish it alongside the verifying key so external parties can:

- Confirm the list of participants.
- Verify that each contribution was computed correctly from the previous one.
- Recompute the verifying key independently (once key derivation is implemented).

---

## Verification

### As a participant

After your contribution is published, you should:

1. Verify the **next** participant's contribution was computed correctly from yours (see Participant Guide, Step 6).
2. When the ceremony finishes, download the final transcript and verify that your contribution appears in the correct position in the chain.

### As an external auditor

Given a published transcript (`ceremony_final.json`) and a verifying key (`chronos.vk`):

1. **Check the challenge chain**: The transcript includes hashes that bind each contribution to the previous one. A tampered transcript will fail this check.

2. **Recompute the verifying key** (once key derivation is implemented): Deserialize the Phase 2 parameters and derive the verifying key yourself. Compare it byte-for-byte to the published key.

3. **Verify each contribution's proof of knowledge**: For each step in the chain, confirm that the pairing checks and Schnorr-like proofs are valid.

The ceremony CLI's `verify` command automates step 3 for a single contribution. A full-chain verifier is planned.

---

## Technical details

### Cryptographic construction

**Phase 1** follows the [Powers of Tau](https://eprint.iacr.org/2017/1050) pattern (BGM17):

- Goal: compute { [τⁱ]₁, [τⁱ]₂ } for i = 0..n without anyone knowing τ.
- Participant j samples τⱼ ← 𝔽ᵣ, computes `new[i] = old[i]^τⱼ` for each power, and proves knowledge of τⱼ via a Schnorr-like proof:
  - Commit: `R = [r]₁` where r ← 𝔽ᵣ
  - Challenge: `c = H(R, new_params)`
  - Response: `s = r + c·τⱼ mod |𝔽ᵣ|`
  - Verification: `[s]₁ = R + c·new[1]₁`
- The final τ = ∏ⱼ τⱼ, known to nobody if one participant destroyed their τⱼ.

**Phase 2** specializes the universal SRS to the Groth16 QAP for the CHRONOS erasure circuit. Additional randomness (α, β) binds the circuit's A, B, C polynomials.

**Pairing checks** confirm that each contribution preserves the τ structure:
- For Phase 1: `e([τⁱ]₁, [τ]₂) = e([τⁱ⁺¹]₁, [1]₂)` for all i.
- We batch these checks with random linear combinations to reduce the verification cost from O(n) pairings to O(1).

### File format

Ceremony state is serialized as JSON with base64-encoded binary blobs. The schema:

```json
{
  "phase": "phase1" | "phase2",
  "num_powers": 16384,
  "phase1_parameters": "<base64-encoded arkworks-serialized G1/G2 points>",
  "phase2_parameters": "<base64-encoded Phase 2 data>",
  "contributors_phase1": ["alice", "bob", "charlie"],
  "contributors_phase2": ["dave", "eve"]
}
```

Group elements use arkworks' compressed serialization: 32 bytes per G1 point, 64 bytes per G2 point.

### Performance

On an Intel Core i5 (8 cores, 3.5 GHz):

| Phase | Powers | Contribution time | Verification time |
|-------|--------|-------------------|-------------------|
| 1     | 4096   | ~15 sec           | ~200 ms           |
| 1     | 16384  | ~60 sec           | ~800 ms           |
| 2     | any    | ~2 sec            | ~50 ms            |

Contribution is CPU-bound (scalar-point multiplications). Verification is dominated by 2–4 pairing operations.

### Parameter sizes

| Powers | Phase 1 parameters size | Phase 2 parameters size |
|--------|------------------------|-------------------------|
| 4096   | ~400 KB                | ~400 KB + circuit data  |
| 16384  | ~1.6 MB                | ~1.6 MB + circuit data  |

Files compress well (gzip reduces by ~40%).

---

## FAQ

### How many participants do I need?

**One honest participant is sufficient** for security, but more is better:

- **Social trust**: If the ceremony has 10 participants from different organizations and countries, an adversary must compromise all 10 to recover the trapdoor. That's harder than compromising one person.
- **Auditability**: A larger, more diverse participant set is more credible to external observers.

Typical ceremonies have 5–100 participants. CHRONOS aims for at least **5 in Phase 1** and **3 in Phase 2**.

### Can I contribute anonymously?

Yes, but with caveats:

- The coordinator and other participants will see the `--contributor` name you provide. You can use a pseudonym.
- However, if you want your contribution to **increase trust**, you should identify yourself (or your organization) publicly so auditors know a real, independent party participated.

### What if a participant ghosts?

The coordinator should set a **deadline** for each contribution (e.g., 48 hours). If a participant doesn't submit by the deadline, the coordinator skips them and sends the challenge to the next person.

The ceremony can proceed with as few participants as desired, but remember: **one honest participant suffices**. If only one person shows up and completes both phases, that's enough.

### What if I made a mistake during my contribution?

Contact the coordinator immediately. If your contribution has already been verified and published, it's part of the chain. If verification failed, the coordinator will send you the previous state again and you can retry.

### Can I run this on a cloud VM?

You can, but it reduces trust slightly: the cloud provider could snapshot your VM's memory during contribution and extract τ. For maximum security, run the contribution binary on a **local, air-gapped machine** that you reboot afterward.

### What's the difference between this and Zcash's ceremony?

Structurally, they're the same (Powers of Tau + circuit-specific phase). Differences:

- Zcash Sapling used BLS12-381; CHRONOS uses BN254.
- Zcash allowed parallel contribution trees; CHRONOS serializes contributions for simplicity.
- Zcash's ceremony had ~90 participants and took months. CHRONOS aims for a faster, smaller ceremony (5–10 participants over 1–2 weeks).

### How do I know the coordinator isn't cheating?

You don't have to trust the coordinator, because:

- **Each contribution is self-verifying**: The cryptographic proofs mean a malicious contribution will fail verification.
- **You verify the next contribution**: If the coordinator tries to insert a fake contribution after yours, you'll detect it when you check the chain.
- **The final transcript is public**: Anyone can audit it.

The coordinator's job is **coordination**, not trust. They could delay the ceremony or DoS it by rejecting valid contributions, but they can't forge proofs or alter the final parameters without detection.

---

## Support

Questions or issues? Open an issue on the CHRONOS GitHub repository or contact the maintainers:

- GitHub: [github.com/ChronosResearch/project-chronos](https://github.com/ChronosResearch/project-chronos)
- ORCID: 0009-0001-7379-955X

---

## License

This ceremony tooling is part of CHRONOS and licensed under AGPL-3.0. See `LICENSE` in the repository root.
