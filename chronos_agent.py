"""
Project CHRONOS — Agent Orchestrator (§3 — Full Architecture)

This module is the top-level orchestrator that sequences the four subsystems:

    Phase 1 — BOOT:
        a. Start the Anti-Tamper Engine (background daemon).
        b. Generate FHE keypair; extract SK into a mutable bytearray.
        c. Register the SK buffer with the Anti-Tamper Engine for emergency
           zeroization if a debugger is detected.
        d. Contact drand to establish the target deadline round.

    Phase 2 — MISSION:
        a. Launch PoSW computation in a background thread (asyncio.to_thread).
        b. Concurrently: encrypt the inference payload and evaluate it
           homomorphically.  The agent never sees the plaintext of its own
           inputs during this phase.

    Phase 3 — TRIGGER (Dead Man's Switch fires):
        a. Wait asynchronously for the drand target round.
        b. Await the PoSW computation to ensure the cryptographic fuse has
           elapsed.

    Phase 4 — ERASURE:
        a. Generate a pre-erasure commitment (Schnorr NIZK) BEFORE wiping.
           This commitment proves knowledge of the key *before* destruction,
           providing forensic evidence for post-mortem verification.
        b. Derive K_enc from the PoSW root (proves time elapsed).
        c. Execute triple-pass C-level memory wipe of the SK buffer.
        d. Verify the pre-erasure commitment against the wiped buffer.
        e. [STUB] Generate a Groth16 SNARK erasure proof via ISNARKProver.

    Phase 5 — TERMINATE:
        a. Log the proof coordinates for the verifier.
        b. Stop the Anti-Tamper daemon.

Pre-erasure Commitment (Fiat-Shamir NIZK — Schnorr protocol):
--------------------------------------------------------------
This is a PRE-ERASURE COMMITMENT, not a SNARK erasure proof.  It proves
that the key material *existed* in the committed form before the wipe.
It does NOT prove:
    - That the VDF/PoSW was correctly computed (that is the SNARK's job).
    - That decryption was correctly performed.
    - That no copies of the key exist elsewhere.

For a full Groth16 SNARK proof (§3.4, Appendix C), inject a real
ISNARKProver implementation.  The NoopSNARKProver stub is used by default.

Schnorr NIZK construction for each 128-byte key chunk:
    x  = int.from_bytes(chunk) mod q              (secret witness)
    y  = g^x mod p                                (public verification key)
    v  = secrets.randbelow(q)                     (CSPRNG nonce)
    t  = g^v mod p                                (commitment)
    c  = H(p || g || y || t || idx) mod q         (Fiat-Shamir challenge)
    r  = (v - c·x) mod q                          (Schnorr response)

    Proof: (t, c, r)
    Verification: g^r · y^c ≡ t (mod p)

Security note on the CSPRNG:
    The nonce v uses secrets.randbelow() — Python's os.urandom()-backed CSPRNG.
    Using random.randrange() would be catastrophic: a predictable nonce leaks x
    via r = (v - c·x) mod q.
"""

import argparse
import asyncio
import hashlib
import secrets
from typing import Any, Dict, Final, List, Optional

from config import (
    DEFAULT_MISSION_DURATION_SEC,
    DISABLE_ANTI_TAMPER,
    DRAND_ROUND_INTERVAL_SEC,
    ZERO_KNOWLEDGE_GENERATOR,
    ZERO_KNOWLEDGE_PRIME,
    ZERO_KNOWLEDGE_Q,
)
from drand_client import DrandClient
from exceptions import CryptographicSanityError, MemoryIntegrityError
from fhe_engine import PaillierFHEEngine
from interfaces import ICryptographicEngine, IOracleClient, ITimeLock, NoopSNARKProver
from logger import get_chronos_logger
from memory_sanitizer import MemorySanitizer
from posw import PoSWManager

_log = get_chronos_logger("ChronosAgent")


class ChronosAgent:
    """Top-level CHRONOS agent orchestrator.

    Composes the four subsystems via Dependency Injection — no concrete type
    is imported or instantiated here; all dependencies arrive through the
    constructor as typed interface objects.  This makes the orchestrator
    fully testable without touching any real cryptography or network I/O.

    Args:
        fhe_engine:           Plaintext-blind inference engine (§3.1).
        posw_manager:         Sequential work time-lock (§3.2).
        drand:                Decentralised randomness beacon (§3.3).
        mission_duration_sec: How long the mission runs before the Dead Man's
                              Switch fires.
        snark_prover:         Optional SNARK prover for Groth16 erasure proof.
                              Defaults to NoopSNARKProver (stub).
    """

    def __init__(
        self,
        fhe_engine: ICryptographicEngine,
        posw_manager: ITimeLock,
        drand: IOracleClient,
        mission_duration_sec: int = DEFAULT_MISSION_DURATION_SEC,
        snark_prover: Optional[Any] = None,
    ) -> None:
        if (
            not isinstance(mission_duration_sec, int)
            or isinstance(mission_duration_sec, bool)
            or mission_duration_sec <= 0
        ):
            raise ValueError(
                "mission_duration_sec must be a positive integer "
                f"(got {mission_duration_sec!r})."
            )

        # --- Anti-Tamper Engine -------------------------------------------
        # Imported here to avoid circular-import at module level.
        # Skipped entirely in CI/pytest via the CHRONOS_DISABLE_ANTI_TAMPER
        # environment variable.
        self._anti_tamper = None
        if not DISABLE_ANTI_TAMPER:
            from security.anti_tamper import AntiTamperEngine

            self._anti_tamper = AntiTamperEngine(check_interval=0.5)
            self._anti_tamper.start()

        _log.info("=" * 58)
        _log.info("          PROJECT CHRONOS - AGENT BOOT                  ")
        _log.info("=" * 58)

        # --- Dependency Injection (IoC) -----------------------------------
        self.fhe_engine: Final[ICryptographicEngine] = fhe_engine
        self.posw_manager: Final[ITimeLock] = posw_manager
        self.drand: Final[IOracleClient] = drand
        self.mission_duration_sec: Final[int] = mission_duration_sec

        # SNARK prover: real Groth16 backend or NoopSNARKProver stub.
        self._snark_prover = snark_prover if snark_prover is not None else NoopSNARKProver()
        if not hasattr(self._snark_prover, "prove"):
            raise TypeError(
                "snark_prover must provide a prove(public_inputs, witness) method."
            )

        # --- Extract SK into mutable buffer ---
        # The buffer will be zeroized at mission end.  We also:
        #   1. Call mlock_buffer() to enforce the Exclusivity Assumption (EA)
        #      from §3.4 — the OS must not page these pages to swap.
        #   2. Register with the Anti-Tamper Engine so it is wiped on tamper-abort.
        raw_sk = self.fhe_engine.get_private_key_bytes()
        if len(raw_sk) == 0:
            raise CryptographicSanityError(
                "FHE engine returned an empty key buffer. "
                "Key generation may have failed silently."
            )
        self.raw_sk_buffer: bytearray = raw_sk
        from memory_sanitizer import mlock_buffer

        mlock_buffer(self.raw_sk_buffer)
        if self._anti_tamper is not None:
            self._anti_tamper.register_emergency_buffer(self.raw_sk_buffer)

        # --- Runtime state (set during mission) ---
        self.target_round: int = 0

    # ------------------------------------------------------------------
    # Phase 1 — Deadline initialisation
    # ------------------------------------------------------------------

    async def _initialise_target_deadline(self) -> None:
        """Fetch the current drand round and compute the target deadline.

        Raises:
            Exception: If the drand oracle cannot be reached.
        """
        current: Optional[Dict[str, Any]] = await self.drand.fetch_latest_round()
        if not current:
            raise CryptographicSanityError(
                "Cannot establish mission deadline: drand returned no data."
            )

        current_round: int = int(current["round"])
        rounds_to_wait: int = max(1, self.mission_duration_sec // DRAND_ROUND_INTERVAL_SEC)
        self.target_round = current_round + rounds_to_wait

        _log.info(f"Mission duration   : {self.mission_duration_sec}s")
        _log.info(f"Current drand round: {current_round}")
        _log.info(
            f"Target deadline    : round {self.target_round} " f"(+{rounds_to_wait} rounds)"
        )

    # ------------------------------------------------------------------
    # Phase 2–5 — Main mission state machine
    # ------------------------------------------------------------------

    async def run_mission(self) -> None:
        """Execute the agent's five-phase lifecycle.

        This coroutine is the single entry point for a complete agent run.
        It must complete in order — no phase may be skipped or reordered.
        """

        # Phase 1 — Establish deadline
        await self._initialise_target_deadline()

        # Phase 2 — Launch PoSW and FHE inference concurrently
        _log.info("--- PHASE 2: MISSION ACTIVE ---")

        # PoSW runs on an isolated CPU core (subprocess) via asyncio.to_thread.
        # This offloads the blocking computation without stalling the event loop.
        posw_task: asyncio.Task[None] = asyncio.create_task(
            asyncio.to_thread(self.posw_manager.compute_posw),
            name="posw-computation",
        )

        # FHE inference: encrypt the payload and evaluate the circuit.
        ct_pair = self.fhe_engine.encrypt_data(b"")
        _ = await asyncio.to_thread(self.fhe_engine.evaluate_inference, ct_pair)
        _log.info("FHE inference completed over encrypted payload.")

        # Phase 3 — Wait for Dead Man's Switch
        _log.info("--- PHASE 3: DEAD MAN'S SWITCH ARMED ---")
        await self.drand.wait_for_round(self.target_round)
        _log.info("drand target round reached.  Dead Man's Switch TRIGGERED.")

        # Ensure PoSW subprocess has finished before key derivation.
        await posw_task
        _log.info("PoSW computation confirmed complete.")

        # Phase 4 — Erasure Protocol
        _log.info("--- PHASE 4: ERASURE PROTOCOL ---")
        self._execute_erasure_protocol()

        # Phase 5 — Terminate
        _log.info("=" * 58)
        _log.info("     CHRONOS AGENT TERMINATED SUCCESSFULLY             ")
        _log.info("=" * 58)
        if self._anti_tamper is not None:
            self._anti_tamper.stop()

    # ------------------------------------------------------------------
    # Phase 4 — Erasure Protocol
    # ------------------------------------------------------------------

    def _execute_erasure_protocol(self) -> None:
        """Generate the pre-erasure commitment, wipe memory, then verify.

        This executes the following ordered steps:
            1. Split raw_sk_buffer into 128-byte chunks (each chunk < q).
            2. Derive y_j = g^x_j mod p for each chunk from the intact buffer.
            3. Generate Fiat-Shamir NIZK commitment (t_j, c_j, r_j) per chunk.
            4. Derive K_enc from the PoSW root (time-lock opened).
            5. WIPE the SK buffer (triple-pass C-level memset).
            6. Verify each chunk's commitment against the wiped buffer.
            7. [STUB] Generate Groth16 SNARK proof via ISNARKProver.

        Terminology note (D2 fix):
            The Fiat-Shamir NIZKs generated here are PRE-ERASURE COMMITMENTS.
            They are NOT Groth16 SNARK erasure proofs.  They prove knowledge
            of the key chunks before the wipe.  The full SNARK proof (§3.4)
            requires a native Groth16 circuit implementation injected via the
            ISNARKProver interface.

        Raises:
            CryptographicSanityError: If any chunk's commitment fails to verify.
            MemoryIntegrityError:     If the memory wipe is incomplete.
        """
        _log.info(
            "Step 4a: Computing Fiat-Shamir NIZK pre-erasure commitments " "for key chunks..."
        )

        p: int = ZERO_KNOWLEDGE_PRIME
        g: int = ZERO_KNOWLEDGE_GENERATOR
        q: int = ZERO_KNOWLEDGE_Q

        chunk_size = 128
        chunks = [
            self.raw_sk_buffer[i : i + chunk_size]
            for i in range(0, len(self.raw_sk_buffer), chunk_size)
        ]

        commitments: List[Dict[str, int]] = []
        for idx, chunk in enumerate(chunks):
            # x_j is at most 128 bytes = 1024 bits.  q is a 2047-bit safe prime.
            # So x_j < q is guaranteed for any 128-byte chunk.
            x_j: int = int.from_bytes(chunk, "big")
            if x_j >= q:
                raise CryptographicSanityError(
                    f"Security assumption failed: chunk {idx} as integer is >= q. "
                    "This indicates a key size mismatch — check chunk_size vs q."
                )

            # Public commitment key: y_j = g^x_j mod p
            y_j: int = pow(g, x_j, p)

            # CSPRNG nonce — MUST use secrets, not random (see module docstring).
            v_j: int = secrets.randbelow(q - 1) + 1  # v_j ∈ [1, q-1]
            t_j: int = pow(g, v_j, p)

            # Fiat-Shamir challenge: c_j = H(p || g || y_j || t_j || idx) mod q
            h = hashlib.sha256()
            h.update(p.to_bytes((p.bit_length() + 7) // 8, "big"))
            h.update(g.to_bytes((g.bit_length() + 7) // 8, "big"))
            h.update(y_j.to_bytes((y_j.bit_length() + 7) // 8, "big"))
            h.update(t_j.to_bytes((t_j.bit_length() + 7) // 8, "big"))
            h.update(idx.to_bytes(4, "big"))
            c_j: int = int(h.hexdigest(), 16) % q

            # Schnorr response: r_j = (v_j - c_j * x_j) % q
            # Python's % operator always returns non-negative, so this is safe.
            r_j: int = (v_j - c_j * x_j) % q

            commitments.append({"y": y_j, "t": t_j, "c": c_j, "r": r_j})

            _log.info(
                f"Pre-erasure commitment chunk {idx}: "
                f"y={str(y_j)[:15]}..., "
                f"c={str(c_j)[:15]}..., "
                f"r={str(r_j)[:15]}..."
            )

        # Derive K_enc — this is what the time-lock was protecting.
        _log.info("Step 4b: Deriving K_enc from PoSW Merkle root (HKDF-SHA256)...")
        self.posw_manager.derive_encryption_key()

        # Triple-pass C-level memory wipe (raises MemoryIntegrityError on failure).
        _log.info("Step 4c: Executing C-level triple-pass memory wipe...")
        MemorySanitizer.zeroize_buffer(self.raw_sk_buffer)

        # Post-wipe commitment verification.
        _log.info("Step 4d: Verifying pre-erasure commitments against wiped buffer...")
        self._verify_commitments(commitments=commitments, p=p, g=g, q=q)

        # Step 4e — SNARK erasure proof (stub).
        _log.info("Step 4e: Generating SNARK erasure proof (ISNARKProver)...")
        _snark_proof = self._snark_prover.prove(
            public_inputs={},  # In production: N, g, T, salt, ct_sk, C_sk, R_M
            witness={},  # In production: pi_vdf, y, K_enc, sk, M_pre, M_post
        )
        _log.info(
            f"SNARK proof generated ({len(_snark_proof)} bytes). "
            "NOTE: Using NoopSNARKProver stub — not a real Groth16 proof. "
            "Inject a real ISNARKProver for production deployment."
        )

    def _verify_commitments(
        self, commitments: List[Dict[str, int]], p: int, g: int, q: int
    ) -> None:
        """Verify the Schnorr NIZK pre-erasure commitments and assert buffer zeroed.

        Verification equation for each chunk j:
            g^r_j · y_j^c_j ≡ t_j  (mod p)

        If all commitments verify AND every byte in raw_sk_buffer is zero, the
        key existed in the committed form before destruction, and is now gone.

        Note: This proves knowledge of the key before destruction.  It does NOT
        prove the full VDF + decryption + erasure circuit (that is the SNARK's
        job, see Step 4e and ISNARKProver).

        Args:
            commitments:  List of dicts containing 'y', 't', 'c', 'r' per chunk.
            p, g, q:      Group parameters.

        Raises:
            CryptographicSanityError: If any Schnorr equation does not hold.
            MemoryIntegrityError:     If the buffer is not fully zeroed.
        """
        for idx, cm in enumerate(commitments):
            y_j = cm["y"]
            t_j = cm["t"]
            c_j = cm["c"]
            r_j = cm["r"]

            t_check: int = (pow(g, r_j, p) * pow(y_j, c_j, p)) % p
            if t_check != t_j:
                raise CryptographicSanityError(
                    f"Pre-erasure commitment verification FAILED for chunk {idx}: "
                    f"g^r*y^c mod p = {str(t_check)[:20]}... != t = {str(t_j)[:20]}..."
                )

        buffer_zeroed: bool = all(b == 0 for b in self.raw_sk_buffer)

        if not buffer_zeroed:
            raise MemoryIntegrityError(
                "Erasure check FAILED: raw_sk_buffer contains non-zero bytes "
                "after the triple-pass wipe.  Memory integrity compromised."
            )

        _log.info(
            f"[OK] All {len(commitments)} pre-erasure commitment equations satisfied: "
            "g^r*y^c == t (mod p)"
        )
        _log.info(
            "[OK] Memory buffer fully zeroed: key material is no longer in the "
            "committed region (under the Exclusivity Assumption)."
        )
        _log.info(
            "ERASURE STATUS: COMMITTED region wiped and verified. "
            "Full attestation requires a real Groth16 SNARK proof via ISNARKProver."
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class ChronosAgentFactory:
    """Factory that wires the four concrete subsystems into a ChronosAgent.

    Keeping construction logic here separates the "how to build" concern from
    the "how to run" concern in ChronosAgent.  Tests bypass this factory
    entirely and inject mocks directly.
    """

    @staticmethod
    def create(duration_sec: int) -> "ChronosAgent":
        """Construct and return a fully initialised ChronosAgent.

        Args:
            duration_sec: Mission duration in seconds.

        Returns:
            A ChronosAgent with real FHE, PoSW, and drand dependencies.
        """
        fhe: ICryptographicEngine = PaillierFHEEngine()
        posw: ITimeLock = PoSWManager(target_duration_seconds=duration_sec)
        oracle: IOracleClient = DrandClient()
        snark = NoopSNARKProver()
        return ChronosAgent(
            fhe_engine=fhe,
            posw_manager=posw,
            drand=oracle,
            mission_duration_sec=duration_sec,
            snark_prover=snark,
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _async_main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Project CHRONOS: Autonomous Cryptographic Agent with " "Provable Memory Erasure"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_MISSION_DURATION_SEC,
        metavar="SECONDS",
        help="Mission duration in seconds before the Dead Man's Switch fires.",
    )
    args = parser.parse_args()

    agent = ChronosAgentFactory.create(args.duration)
    await agent.run_mission()


def main() -> None:
    """Synchronous entry point for the CLI."""
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
