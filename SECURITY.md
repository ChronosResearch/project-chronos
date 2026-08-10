# CHRONOS Security Analysis

## UC Security Theorem

**Theorem 1 (UC-Erasure).** Let `λ` be the security parameter. Assume:

- `(G, H)` is a `(T, ε_vdf)`-sequential VDF (Boneh et al., 2018) — no adversary
  running in time `o(T)` can compute `y = g^(2^T) mod N` with advantage > `ε_vdf`.
- `AES-256-GCM` is `(t, ε_aes)`-IND-CCA2 secure.
- `HKDF-SHA256` is a `(t, ε_hkdf)`-secure PRF (modelled as a random oracle).
- `Groth16` over BN254 is `(t, ε_snark)`-knowledge-sound (Groth, 2016).
- `Dilithium3` is `(t, ε_pq)`-EUF-CMA secure under Module-LWE (NIST FIPS 204).

Then the CHRONOS protocol UC-realizes the ideal functionality `F_CHRONOS` in the
`F_OS`-hybrid model with advantage at most:

```
ε_total ≤ ε_vdf + ε_aes + ε_hkdf + ε_snark + ε_pq + negl(λ)
```

against any PPT environment `Z` and adversary `A`.

---

## Ideal Functionality F_CHRONOS

```
F_CHRONOS operates as follows:

  Init(mission_id, T):
    - Record (mission_id, T, g, N).
    - Sample sk ← {0,1}^256.
    - Compute ct_sk ← AES-GCM-Enc(K_enc, sk) where K_enc = HKDF(y, salt).
    - Output ct_sk to the environment.
    - Start internal clock counting T sequential steps.

  Infer(ct_input):
    - If clock < T: evaluate FHE(ct_input) under sk; return result.
    - Else: return ⊥.

  Erase():
    - Triggered when clock = T (or watchdog fires).
    - Wipe sk from all storage.
    - Compute π_erase ← Groth16.Prove(sk=0, m_pre, y, salt, ct_sk, g, N, π_vdf).
    - Output (erased, π_erase, R, σ_pq) where:
        R = SHA-256(y)  (identity root)
        σ_pq = Dilithium3.Sign(sk_pq, SHA-256(R || mission_id))

  Verify(π_erase):
    - Return Groth16.Verify(vk, π_erase, public_inputs).
```

---

## Simulator S

The simulator `S` operates in the ideal world against `F_CHRONOS`:

1. **Init phase**: `S` receives `(mission_id, T, ct_sk)` from `F_CHRONOS`.
   `S` simulates the VDF by programming the random oracle: sets `y* ← {0,1}^256`
   and defines `H(g, T, N) := y*`. This is indistinguishable from a real VDF
   output by the sequentiality assumption (no PPT adversary can distinguish
   `g^(2^T) mod N` from a random group element in time `o(T)`).

2. **Infer phase**: `S` forwards FHE ciphertexts to `F_CHRONOS` and relays
   responses. The FHE semantic security ensures the environment learns nothing
   about `sk` from ciphertexts.

3. **Erase phase**: `S` must produce a valid `π_erase` without knowing `sk`.
   By the Groth16 zero-knowledge property, `S` uses the simulator trapdoor
   `τ` (from the trusted setup) to produce a simulated proof `π_sim` that is
   computationally indistinguishable from a real proof. The public inputs
   `(y[0], wipe_pattern)` are set consistently with `y*`.

4. **Identity phase**: `S` generates a fresh Dilithium3 key pair `(pk_sim, sk_sim)`
   and signs `SHA-256(R || mission_id)` with `sk_sim`. The EUF-CMA security of
   Dilithium3 ensures no environment can distinguish `σ_sim` from a real signature
   without the secret key.

**Indistinguishability argument**: The real and ideal executions are
indistinguishable because:
- The VDF output is pseudorandom (sequentiality assumption).
- `K_enc = HKDF(y, salt)` is pseudorandom (PRF assumption on HKDF).
- `ct_sk` is semantically secure (IND-CCA2 of AES-GCM).
- `π_erase` is zero-knowledge (Groth16 ZK property).
- `σ_pq` is unforgeable (Dilithium3 EUF-CMA).

A hybrid argument over these five properties gives `ε_total` as stated.

---

## F_OS Hybrid Model

The `F_OS` (Operational Security) ideal functionality captures the Exclusivity
Assumption (EA): the agent process has exclusive access to its memory pages
during execution. Concretely, `F_OS` guarantees:

- `RLIMIT_CORE = 0` (no core dumps).
- `PR_SET_DUMPABLE = 0` (no ptrace attach).
- `mlock` on all secret-bearing pages (no swap).
- Triple-pass volatile wipe on `Drop` (compiler fence prevents optimization).

The EA is verified at startup (`verify_ea`) and enforced by the OS kernel.
Any adversary that violates the EA is outside the threat model.

**Open gap**: The `F_OS` axiom is assumed, not derived from lower-level
primitives. A full reduction would require a hardware security model (e.g.,
Intel TDX or AMD SEV-SNP attestation). This is left as future work.

---

## Known Gaps (Prototype)

| Gap | Status | Impact |
|-----|--------|--------|
| Groth16 AES-GCM gadget simulates constraints, not real AES-GCM | Prototype | Proof not binding to actual AES-GCM computation |
| MPC trusted setup is simulated (3-party local XOR) | Prototype | Toxic waste not distributed across real parties |
| `certN.bin` falls back to hardcoded RSA-2048 | Prototype | VDF group order not from a real MPC ceremony |
| UC proof is a structured sketch, not machine-checked | Research | Reviewer concern — Coq/Lean proof needed for top-tier |
| `F_OS` is axiomatized, not reduced to hardware attestation | Research | Strongest security claim unproven without TDX/SEV-SNP |

---

## References

- Boneh, D., Bonneau, J., Bünz, B., Fisch, B. (2018). *Verifiable Delay Functions*. CRYPTO 2018.
- Groth, J. (2016). *On the Size of Pairing-Based Non-interactive Arguments*. EUROCRYPT 2016.
- NIST FIPS 204 (2024). *Module-Lattice-Based Digital Signature Standard (ML-DSA)*.
- Canetti, R. (2001). *Universally Composable Security*. FOCS 2001.
- Bellare, M., Rogaway, P. (1993). *Random Oracles are Practical*. CCS 1993.
