//! End-to-end lifecycle test: the whole CHRONOS claim in one place.
//!
//! Every other test in this workspace checks one component. This one walks the
//! actual protocol across the provisioner/agent trust boundary and asserts that
//! the erasure proof verifies against commitments the agent never chose:
//!
//! ```text
//! PROVISIONER                          AGENT                        VERIFIER
//! -----------                          -----                        --------
//! y  = g^(2^T) mod N
//! K  = Poseidon-KDF(y, salt)
//! sk <- random
//! ct = AEAD_K(sk)
//! publish {y,ct,sk,mission}_commit  ->  ct, salt, artifact
//!                                       y' = g^(2^T) mod N   <-- real work
//!                                       K' = KDF(y', salt)
//!                                       sk' = AEAD_open(ct)
//!                                       run containment -> Erased
//!                                       prove(witness)        ->    verify(proof, artifact)
//! ```
//!
//! The squarings are performed for real on both sides — no `φ(N)` shortcut — since
//! the property under test is precisely that the key is recoverable *only* by
//! doing the sequential work.
//!
//! `T` is small so the suite stays fast. `T` does not affect what is being
//! demonstrated: the derivation chain is identical at `T = 1_000` and
//! `T = 1_000_000`, only the wall time differs.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use chronos_core::containment::{ContainmentLedger, ContainmentState, Event, Phase};
use chronos_core::mpc::MpcCertificate;
use chronos_core::VdfEngine;
use chronos_snark::aead::{ChronosAead, Ciphertext};
use chronos_snark::circuit::{
    ContainmentSummary, ErasureWitness, MISSION_BYTES, SALT_BYTES, SK_BYTES, WIPE_PATTERN, Y_BYTES,
};
use chronos_snark::identity_circuit::{identity_root, mission_id_to_bytes, IdentityProver};
use chronos_snark::mission::MissionPublic;
use chronos_snark::poseidon::{self, Domain};
use chronos_snark::prover::{Groth16Prover, SetupContribution, SetupTranscript};
use chronos_vdf::wesolowski::WesolowskiVdf;
use num_bigint::BigUint;

/// Sequential squarings. Small for test speed; see the module note.
const T: u64 = 1_000;

/// Left-pad to the circuit's fixed `y` width.
fn to_fixed_be(v: &BigUint, len: usize) -> Vec<u8> {
    let be = v.to_bytes_be();
    assert!(
        be.len() <= len,
        "value is {} bytes, wider than the circuit's fixed width of {len}",
        be.len()
    );
    let mut out = vec![0u8; len];
    out[len - be.len()..].copy_from_slice(&be);
    out
}

/// What the provisioner publishes, plus what it hands the agent privately.
struct Provisioned {
    artifact: MissionPublic,
    ct: Ciphertext,
    salt: Vec<u8>,
    modulus: BigUint,
    mission_digest: [u8; MISSION_BYTES],
    /// Retained by the test only, to assert the agent recovers exactly this.
    /// A real provisioner wipes it.
    sk_for_assertion: [u8; SK_BYTES],
}

/// Run the provisioner side.
fn provision(mission_id: &str) -> Provisioned {
    let n = MpcCertificate::load("/nonexistent")
        .expect("prototype modulus must load")
        .n;
    let g = BigUint::from(2u32);

    // Real sequential work — this test does not use the φ(N) shortcut.
    let vdf = WesolowskiVdf;
    let (y, _proof) = vdf.evaluate(&g, T, &n).expect("VDF evaluation must succeed");
    let y_fixed = to_fixed_be(&y, Y_BYTES);

    let salt: Vec<u8> = (0..SALT_BYTES).map(|i| (i as u8).wrapping_mul(31)).collect();
    let k_enc = ChronosAead::derive_key(&y_fixed, &salt);

    let mut sk = [0u8; SK_BYTES];
    for (i, b) in sk.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(9);
    }

    let nonce = Fr::from_be_bytes_mod_order(&[0xA5u8; 16]);
    let ct = ChronosAead::encrypt(&k_enc, nonce, &poseidon::split32(&sk)).expect("sealing");

    let mission_digest = mission_id_to_bytes(mission_id);

    let artifact = MissionPublic::new(
        mission_id.to_string(),
        T,
        600,
        poseidon::hash_bytes(Domain::VdfOutput, &y_fixed),
        poseidon::hash(Domain::Ciphertext, &ct.to_elements()),
        poseidon::hash(Domain::SecretKey, &poseidon::split32(&sk)),
        poseidon::hash_bytes(Domain::MissionId, &mission_digest),
        8,
        128,
    );

    Provisioned {
        artifact,
        ct,
        salt,
        modulus: n,
        mission_digest,
        sk_for_assertion: sk,
    }
}

/// Run a containment ledger through a realistic mission to its terminal state.
fn run_containment(artifact: &MissionPublic) -> ContainmentLedger {
    let mut ledger = ContainmentLedger::new(
        ContainmentState::new(
            artifact.op_budget,
            artifact.disclosure_budget_bits,
            artifact.t_seconds,
        ),
        64,
    );
    assert!(ledger.admit(Event::MissionInit).is_admitted());
    assert!(ledger
        .admit(Event::Infer {
            declared_secs: 1,
            disclosure_bits: 16
        })
        .is_admitted());
    assert!(ledger.admit(Event::KeyReleased).is_admitted());
    assert!(ledger.admit(Event::Erase).is_admitted());
    assert_eq!(ledger.state().phase, Phase::Erased);
    ledger
}

/// The full protocol, provisioner through verifier.
#[test]
fn test_full_mission_lifecycle_verifies() {
    let p = provision("mission-lifecycle-001");

    // ── Agent: perform the sequential work ───────────────────────────────────
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdf;
    let (y_agent, vdf_proof) = vdf
        .evaluate(&g, T, &p.modulus)
        .expect("agent VDF evaluation must succeed");

    // The VDF proof is checked natively in O(log T), outside the SNARK. That is
    // why the circuit does not need 2048-bit modular arithmetic.
    assert!(
        vdf.verify(&g, &y_agent, &vdf_proof, T, &p.modulus),
        "the agent's VDF proof must verify natively"
    );

    let y_fixed = to_fixed_be(&y_agent, Y_BYTES);

    // ── Agent: derive the sealing key and open the ciphertext ────────────────
    let k_enc = ChronosAead::derive_key(&y_fixed, &p.salt);
    let opened = ChronosAead::decrypt(&k_enc, &p.ct)
        .expect("the agent must be able to open ct_sk after completing the VDF");

    let sk_bytes = poseidon::join32(&[opened[0], opened[1]])
        .expect("recovered plaintext must be a 32-byte key");
    assert_eq!(
        sk_bytes, p.sk_for_assertion,
        "the agent must recover exactly the key the provisioner sealed"
    );

    // The recovered key must match the published commitment. This is the check a
    // verifier relies on and the agent cannot fake.
    let [_, _, sk_commit, _] = p.artifact.commitments().expect("artifact must decode");
    assert_eq!(
        poseidon::hash(Domain::SecretKey, &poseidon::split32(&sk_bytes)),
        sk_commit,
        "recovered key must match the provisioner's sk_commit"
    );

    // ── Agent: run containment to a terminal state ───────────────────────────
    let ledger = run_containment(&p.artifact);
    let summary = ContainmentSummary::from_ledger(&ledger);
    assert!(summary.is_terminal());

    // ── Agent: build the witness and prove ───────────────────────────────────
    let witness = ErasureWitness {
        y: y_fixed,
        salt: p.salt.clone(),
        ct: p.ct.clone(),
        sk: sk_bytes,
        m_post: vec![WIPE_PATTERN; SK_BYTES],
        mission_digest: p.mission_digest,
        containment: summary,
    };
    witness
        .check_shape()
        .expect("a witness built from real protocol values must be well formed");

    // The witness-derived public inputs must equal the ones the provisioner
    // published. If these diverge, the agent is proving a different statement
    // than the verifier is checking.
    let derived = witness.public_inputs();
    let expected = p
        .artifact
        .to_public_inputs(summary.commitment())
        .expect("artifact must assemble");
    assert_eq!(
        derived, expected,
        "witness-derived commitments must match the published artifact exactly"
    );

    let mut transcript = SetupTranscript::new();
    transcript.contribute(&SetupContribution::generate("lifecycle-test"));
    let mut prover = Groth16Prover::new();
    prover
        .setup_with_transcript(&transcript)
        .expect("setup must succeed");

    let proof = prover
        .prove_erasure(&witness)
        .expect("proving must succeed for a consistent witness");

    // ── Verifier: nothing but the artifact and the proof ─────────────────────
    assert!(
        prover
            .verify_erasure(&proof, &expected)
            .expect("verification must not error"),
        "the erasure proof must verify against the published mission artifact"
    );
    assert_eq!(proof.len(), 128, "Groth16 proofs are constant-size");
}

/// An agent that did not complete the VDF cannot open the ciphertext, and so
/// cannot build a witness at all. This is the time-lock, demonstrated rather
/// than asserted.
#[test]
fn test_incomplete_vdf_cannot_open_the_ciphertext() {
    let p = provision("mission-shortfall-001");
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdf;

    // One squaring short.
    let (y_short, _) = vdf
        .evaluate(&g, T - 1, &p.modulus)
        .expect("VDF must succeed");
    let k_wrong = ChronosAead::derive_key(&to_fixed_be(&y_short, Y_BYTES), &p.salt);

    assert!(
        ChronosAead::decrypt(&k_wrong, &p.ct).is_err(),
        "stopping even one squaring short must leave the key sealed"
    );
}

/// An agent that completed the VDF but fabricated a key cannot produce a proof:
/// `sk_commit` was fixed by the provisioner.
#[test]
fn test_fabricated_key_cannot_be_proven() {
    let p = provision("mission-fabricate-001");
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdf;
    let (y, _) = vdf.evaluate(&g, T, &p.modulus).expect("VDF");
    let y_fixed = to_fixed_be(&y, Y_BYTES);

    let ledger = run_containment(&p.artifact);

    let witness = ErasureWitness {
        y: y_fixed,
        salt: p.salt.clone(),
        ct: p.ct.clone(),
        // The attack that passed every earlier revision of the circuit.
        sk: [WIPE_PATTERN; SK_BYTES],
        m_post: vec![WIPE_PATTERN; SK_BYTES],
        mission_digest: p.mission_digest,
        containment: ContainmentSummary::from_ledger(&ledger),
    };

    assert!(
        witness.check_shape().is_err(),
        "an all-0xFF buffer presented as the key must be rejected"
    );
}

/// An agent that ran the mission but never erased cannot produce a proof.
/// Proof-carrying containment, demonstrated end to end.
#[test]
fn test_unerased_mission_cannot_be_proven() {
    let p = provision("mission-unerased-001");
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdf;
    let (y, _) = vdf.evaluate(&g, T, &p.modulus).expect("VDF");
    let y_fixed = to_fixed_be(&y, Y_BYTES);

    let k_enc = ChronosAead::derive_key(&y_fixed, &p.salt);
    let opened = ChronosAead::decrypt(&k_enc, &p.ct).expect("open");
    let sk_bytes = poseidon::join32(&[opened[0], opened[1]]).expect("join");

    // Mission started, never erased.
    let mut ledger = ContainmentLedger::new(ContainmentState::new(8, 128, 600), 64);
    ledger.admit(Event::MissionInit);

    let witness = ErasureWitness {
        y: y_fixed,
        salt: p.salt.clone(),
        ct: p.ct.clone(),
        sk: sk_bytes,
        m_post: vec![WIPE_PATTERN; SK_BYTES],
        mission_digest: p.mission_digest,
        containment: ContainmentSummary::from_ledger(&ledger),
    };

    let err = witness
        .check_shape()
        .expect_err("a non-terminal containment run must be refused");
    assert!(
        format!("{err}").contains("not terminal"),
        "error should name the containment failure, got: {err}"
    );
}

/// EAIP over the same mission: the agent proves knowledge of the VDF output
/// behind the published identity root, in zero knowledge.
#[test]
fn test_identity_proof_over_the_same_vdf_output() {
    let p = provision("mission-identity-001");
    let g = BigUint::from(2u32);
    let vdf = WesolowskiVdf;
    let (y, _) = vdf.evaluate(&g, T, &p.modulus).expect("VDF");
    let y_fixed = to_fixed_be(&y, Y_BYTES);

    let root = identity_root(&y_fixed, &p.mission_digest);

    let mut prover = IdentityProver::new();
    prover
        .setup_local_development()
        .expect("identity setup must succeed");

    let proof = prover
        .prove_identity(&y_fixed, &p.mission_digest)
        .expect("identity proving must succeed");

    assert!(
        prover
            .verify_identity(&proof, root)
            .expect("verification must not error"),
        "the identity proof must verify against the published root"
    );

    // An agent one squaring short has a different root and cannot claim this one.
    let (y_short, _) = vdf.evaluate(&g, T - 1, &p.modulus).expect("VDF");
    let root_short = identity_root(&to_fixed_be(&y_short, Y_BYTES), &p.mission_digest);
    assert_ne!(root, root_short, "the root must be time-locked to T");
    assert!(
        !prover
            .verify_identity(&proof, root_short)
            .expect("verification must not error"),
        "a proof for the full-T root must not verify against a short-T root"
    );
}

/// The published artifact must survive a JSON round trip unchanged, since it is
/// transported as a file between three parties.
#[test]
fn test_artifact_round_trips_through_json() {
    let p = provision("mission-artifact-001");
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "chronos-lifecycle-artifact-{}.json",
        std::process::id()
    ));

    p.artifact.save(&path).expect("save");
    let loaded = MissionPublic::load(&path).expect("load");
    assert_eq!(loaded, p.artifact);
    assert_eq!(
        loaded.commitments().expect("decode"),
        p.artifact.commitments().expect("decode")
    );

    std::fs::remove_file(&path).ok();
}
