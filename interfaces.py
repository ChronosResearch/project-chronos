"""
Project CHRONOS — Interface Contracts (Structural Subtyping)

Using typing.Protocol instead of abc.ABC gives us structural subtyping:
any class that implements the required methods satisfies the interface without
inheriting from it.  This keeps test doubles and production implementations
fully decoupled — no base class import needed.

The six contracts map directly to the subsystems described in the paper:
    ICryptographicEngine  →  §3.1  Plaintext Blindness (FHE)
    ITimeLock             →  §3.2  Cryptographic Fuse (PoSW / Hash chain)
    IVDFEngine            →  §3.2  Wesolowski VDF (production replacement)
    IOracleClient         →  §3.3  Dead Man's Switch (drand)
    IMemorySanitizer      →  §3.4  Erasure Protocol (memory wipe)
    ISNARKProver          →  §3.4  SNARK Erasure Attestation (Groth16)

Design note — ISNARKProver and IVDFEngine:
    These two interfaces are STUBS in this prototype.  The paper (§3.3, §3.4)
    specifies Wesolowski VDF over an MPC-generated RSA modulus and a Groth16
    circuit with ~180k constraints.  Both require native Rust/C++ backends
    (bellman, gnark, or arkworks) that have no stable pure-Python bindings.

    Inject the stub implementations (NoopSNARKProver, NoopVDFEngine) during
    development.  Replace with a cffi/ctypes shim to a compiled Rust crate
    for production use.
"""

from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable


@runtime_checkable
class ICryptographicEngine(Protocol):
    """Contract for the Fully Homomorphic Encryption subsystem (§3.1).

    Implementations must provide:
    - Key material extraction as a mutable bytearray (so it can be shredded).
    - Encryption of an arbitrary byte payload.
    - Homomorphic inference evaluation over ciphertexts without decrypting them.
    """

    def get_private_key_bytes(self) -> bytearray:
        """Return the private key as a mutable bytearray.

        The caller owns the buffer and is responsible for zeroizing it via
        MemorySanitizer.zeroize_buffer() after use.
        """
        ...

    def encrypt_data(self, data: bytes) -> Tuple[int, int]:
        """Encrypt a byte payload and return a pair of ciphertexts.

        Returns a tuple of two integer ciphertexts suitable for
        evaluate_inference().
        """
        ...

    def evaluate_inference(self, ciphertexts: Tuple[int, int]) -> int:
        """Perform homomorphic computation over ciphertexts without decrypting.

        Returns a single integer ciphertext representing the encrypted result.
        """
        ...


@runtime_checkable
class ITimeLock(Protocol):
    """Contract for the Proof of Sequential Work time-lock (§3.2).

    The prototype implements this with a SHA-256 hash chain (Cohen 2018 PoSW).
    For production, replace with IVDFEngine which uses the Wesolowski VDF over
    an RSA group with an MPC-generated modulus.

    Implementations must enforce that no shortcut exists to compute the result
    faster than real elapsed wall-clock time (sequential, non-parallelisable).
    """

    def compute_posw(self) -> None:
        """Execute the sequential hash chain.

        This is a blocking, CPU-bound call.  The caller is responsible for
        running it in a thread or subprocess so it does not block the event loop.
        After this returns, derive_encryption_key() may be called.
        """
        ...

    def derive_encryption_key(self) -> bytes:
        """Derive a 256-bit AES key from the PoSW Merkle root via HKDF-SHA256.

        Raises:
            ValueError: If compute_posw() has not been called yet.

        Returns:
            32 raw bytes suitable for use as an AES-256 key.
        """
        ...


@runtime_checkable
class IVDFEngine(Protocol):
    """Contract for the Wesolowski VDF production backend (§3.2, §3.3).

    STUB — not implemented in the prototype.  This interface documents the
    API that a native Wesolowski VDF implementation (e.g., via a Rust crate
    through cffi) must satisfy.

    The Wesolowski VDF construction:
        y = g^{2^T} mod N,  where N is an RSA modulus from a multi-party
        ceremony (Diogenes protocol, CRYPTO 2020).

    The VDF proof π_vdf = (ℓ, r) lets a verifier confirm the sequential
    squaring was completed in O(T / log T) operations rather than T.
    """

    def setup(self, modulus_bits: int, num_parties: int) -> bytes:
        """Run (or simulate) the MPC ceremony to generate the RSA modulus N.

        Args:
            modulus_bits:  Bit-length of N (2048 recommended).
            num_parties:   Number of MPC participants.

        Returns:
            The RSA modulus N as big-endian bytes.  No party learns p or q.
        """
        ...

    def evaluate(self, g: int, T: int, N: bytes) -> Tuple[int, bytes]:
        """Compute y = g^{2^T} mod N via sequential squarings.

        Args:
            g:  Generator element in Z_N*.
            T:  Number of squarings (calibrated to the mission duration).
            N:  RSA modulus as big-endian bytes.

        Returns:
            (y, pi_bytes) where y is the VDF output and pi_bytes is the
            serialized Wesolowski proof (ℓ, r).
        """
        ...

    def verify(self, g: int, T: int, N: bytes, y: int, pi_bytes: bytes) -> bool:
        """Verify the Wesolowski proof in O(T / log T) time.

        Args:
            g, T, N:    Same parameters used in evaluate().
            y:          Claimed VDF output.
            pi_bytes:   Serialized proof from evaluate().

        Returns:
            True if the proof is valid, False otherwise.
        """
        ...


@runtime_checkable
class IOracleClient(Protocol):
    """Contract for the decentralised randomness beacon (§3.3).

    drand provides a publicly verifiable, BLS-threshold-signed random beacon
    that the agent uses as an unforgeable external clock.
    """

    async def fetch_latest_round(self) -> Optional[Dict[str, Any]]:
        """Fetch the most recent round from the drand network.

        Returns:
            A dict with at minimum ``round`` (int), ``signature`` (hex str),
            and ``randomness`` (hex str) keys, or None on failure.

        Raises:
            OracleUnreachableError: On any network or HTTP error.
        """
        ...

    async def wait_for_round(
        self, target_round: int, polling_interval: int = 3
    ) -> Dict[str, Any]:
        """Poll the beacon until *target_round* is reached or exceeded.

        This is the Dead Man's Switch trigger.  It must not block the event loop.

        Args:
            target_round:       The drand round number to wait for.
            polling_interval:   Seconds between successive API calls.

        Returns:
            The full drand round data dict for the first round >= *target_round*.

        Raises:
            CryptographicSanityError: If the beacon's BLS signature fails.
        """
        ...


@runtime_checkable
class IMemorySanitizer(Protocol):
    """Contract for the physical memory erasure protocol (§3.4)."""

    @staticmethod
    def zeroize_buffer(buffer: bytearray) -> None:
        """Perform a secure, multi-pass overwrite of *buffer* in place.

        Args:
            buffer: A mutable bytearray containing sensitive key material.

        Raises:
            TypeError:           If *buffer* is not a bytearray.
            MemoryIntegrityError: If any byte remains non-zero after erasure.
        """
        ...


class ISNARKProver(Protocol):
    """Contract for the Groth16 SNARK erasure prover (§3.4, Appendix C).

    STUB — not implemented in the prototype.  This interface documents the
    API that a native Groth16 circuit prover must satisfy.

    The paper specifies a circuit with ~180,000 R1CS constraints over
    BLS12-381 that proves:
        1. π_vdf is a valid Wesolowski proof.
        2. K_enc = HKDF(y || salt).
        3. sk = AES-GCM-Dec(K_enc, ct_sk, nonce).
        4. C_sk = Poseidon(sk).
        5. R_M = MerkleRoot(M_pre).
        6. M_post = 0^{|M|}.

    Proof parameters (BLS12-381 / Groth16):
        - Proving key: ~50 MB
        - Verification key: ~2 KB
        - Proof size: 192 bytes
        - Verification time: ~15 ms

    Production implementation: arkworks-rs/groth16 or bellman crate via cffi.
    """

    def prove(
        self,
        public_inputs: Dict[str, Any],
        witness: Dict[str, Any],
    ) -> bytes:
        """Generate a Groth16 proof for the erasure circuit.

        Args:
            public_inputs:  Dict containing N, g, T, salt, ct_sk, C_sk, R_M,
                            drand_sig (all as bytes or int).
            witness:        Dict containing pi_vdf, y, K_enc, sk, nonce,
                            M_pre, M_post (private inputs).

        Returns:
            192-byte Groth16 proof (serialized as bytes).
        """
        ...

    def verify(
        self,
        public_inputs: Dict[str, Any],
        proof_bytes: bytes,
    ) -> bool:
        """Verify a Groth16 proof in ~15 ms.

        Args:
            public_inputs:  Same dict structure as prove().
            proof_bytes:    192 bytes returned by prove().

        Returns:
            True if the proof is valid.
        """
        ...


class NoopSNARKProver:
    """Stub ISNARKProver that logs a warning and returns a sentinel.

    Use this during development/testing.  Replace with a real prover bound
    to a compiled Groth16 backend for production deployment.
    """

    def prove(
        self,
        public_inputs: Dict[str, Any],
        witness: Dict[str, Any],
    ) -> bytes:
        import warnings

        warnings.warn(
            "NoopSNARKProver.prove() called — no real Groth16 proof generated. "
            "This is a prototype stub. Do not use in production.",
            stacklevel=2,
        )
        # Return 192 zero bytes as a sentinel (verifiable as a stub proof).
        return b"\x00" * 192

    def verify(
        self,
        public_inputs: Dict[str, Any],
        proof_bytes: bytes,
    ) -> bool:
        import warnings

        warnings.warn(
            "NoopSNARKProver.verify() called — stub always returns False "
            "unless the proof is the 192-zero sentinel from NoopSNARKProver.prove().",
            stacklevel=2,
        )
        return proof_bytes == b"\x00" * 192


class NoopVDFEngine:
    """Stub IVDFEngine that delegates to a SHA-256 hash chain PoSW.

    Use this during development.  Replace with a Wesolowski VDF implementation
    backed by a GMP-accelerated Rust crate for production.
    """

    def setup(self, modulus_bits: int, num_parties: int) -> bytes:
        import warnings

        warnings.warn(
            "NoopVDFEngine.setup() — returning a dummy modulus (NOT from MPC). "
            "VDF sequentiality guarantee is NOT provided. Prototype only.",
            stacklevel=2,
        )
        # Return a dummy big-endian 256-byte integer (not a real RSA modulus).
        import os

        return os.urandom(modulus_bits // 8)

    def evaluate(self, g: int, T: int, N: bytes) -> Tuple[int, bytes]:
        import warnings

        warnings.warn(
            "NoopVDFEngine.evaluate() — returning dummy output. Not a real VDF.",
            stacklevel=2,
        )
        return (0, b"\x00" * 32)

    def verify(self, g: int, T: int, N: bytes, y: int, pi_bytes: bytes) -> bool:
        return False
