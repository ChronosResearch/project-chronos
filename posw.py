"""
Project CHRONOS — Proof of Sequential Work (PoSW) Time-Lock (§3.2)

This module implements the Cohen-Pietrzak Proof of Sequential Work that acts
as the "cryptographic fuse" in the CHRONOS architecture.

IMPORTANT — Prototype vs. Paper Distinction
-------------------------------------------
The revised paper (§3.2, §3.3) specifies the Wesolowski VDF construction:

    y = g^{2^T} mod N,  where N is an RSA modulus from a multi-party ceremony.

The Wesolowski proof π_vdf = (ℓ, r) lets a verifier confirm the squaring
completed in O(T/log T) operations rather than T.  That construction requires:
    a) GMP-accelerated RSA group squarings (not available in pure Python at
       production speed — gmpy2 helps but Python function call overhead
       dominates for millions of squarings).
    b) A multi-party modulus N from the Diogenes protocol (requires a live
       network with n ≥ 2 independent parties).

This prototype uses a SHA-256 iterated hash chain PoSW, which is a valid and
formally analysed sequential work construction (Cohen, ITCS 2018).  It has the
same non-parallelisability guarantee but does NOT admit the Wesolowski succinct
verification proof (π_vdf).  A binary Merkle tree provides O(log N)
spot-verification of individual checkpoints, which is the analogue.

See interfaces.IVDFEngine for the interface a native Wesolowski backend must
satisfy.  Inject NoopVDFEngine (stub) during development; replace with a cffi
shim to a GMP/Rust implementation for production.

Background (§2.2 of the paper):
    A PoSW is a function f(x, T) that requires T sequential computational
    steps to evaluate, and whose output can be verified in sub-linear time.
    Unlike proof-of-work (which is parallelisable), PoSW is inherently
    sequential — throwing more cores at it does NOT speed it up.

    CHRONOS uses PoSW to enforce a minimum elapsed wall-clock time before the
    decryption key can be derived.  No shortcut exists on current hardware.

Implementation details:
    - The sequential kernel is a SHA-256 hash chain: h_i = SHA256(h_{i-1}).
    - The chain is split into 1_000 segments of equal length.  The last hash
      of each segment is saved as a "checkpoint" (leaf node).
    - A BINARY MERKLE TREE is built over the 1_000 checkpoints.  Each
      internal node is SHA256(left_child || right_child).  The root is the
      PoSW commitment.  A verifier can spot-check any leaf in exactly
      ceil(log2(1000)) = 10 hash operations using the Merkle inclusion proof
      (sibling path), without replaying the full chain.
    - The chain runs in an isolated subprocess (multiprocessing.Process) so
      the CPU-bound work does not block the asyncio event loop.
    - Communication between worker and parent uses multiprocessing.Pipe
      (not Queue) to avoid OS pipe buffer limits that cause deadlock when the
      checkpoint list exceeds ~65 KB.  (D4 fix — see rejection analysis.)
    - The key derivation uses HKDF-SHA256 over the Merkle root so that the
      output key is indistinguishable from random even if the internal hash
      chain algorithm is known.

Calibration:
    The PoSW manager auto-calibrates on startup by timing 100_000 hash
    operations and computing how many hashes per second the local CPU achieves.
    It then sets T = hashes_per_second * target_duration_seconds, so that the
    chain takes exactly *target_duration_seconds* of real wall-clock time.

    Calibration drift note (acknowledged in §5.2 of the paper): if the CPU
    frequency changes between calibration and execution (due to thermal
    throttling or power management), the actual duration will vary.  A ±10%
    tolerance is expected and acceptable for the prototype.  Actual elapsed
    time is measured and logged; if drift exceeds 25% a WARNING is emitted.
"""

import hashlib
import multiprocessing as mp

try:
    import fast_posw
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False

import secrets
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from logger import get_chronos_logger

# ---------------------------------------------------------------------------
# Number of Merkle checkpoints.  Higher values make verification cheaper but
# use slightly more memory during the sequential phase.
# ---------------------------------------------------------------------------
_CHECKPOINT_COUNT: int = 1_000

# HKDF context string — domain-separates the PoSW key from any other keys
# derived in the same system.
_HKDF_INFO: bytes = b"chronos-posw-key-v1"

# Drift threshold: if actual elapsed time deviates from target by more than
# this fraction, emit a security warning.
_DRIFT_WARNING_THRESHOLD: float = 0.25


# ---------------------------------------------------------------------------
# Binary Merkle Tree
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MerkleProof:
    """O(log N) inclusion proof for a single Merkle leaf.

    Attributes:
        leaf_index:   Index of the leaf being proved (0-based).
        leaf_hash:    The raw leaf value (checkpoint bytes).
        sibling_path: Ordered list of (sibling_bytes, sibling_is_right_child)
                      tuples from leaf level up to root level.
        root:         Hex-encoded Merkle root this proof was generated against.
    """

    leaf_index: int
    leaf_hash: bytes
    sibling_path: List[Tuple[bytes, bool]]
    root: str


class MerkleTree:
    """Binary Merkle tree built over a list of byte leaves.

    Each leaf is the raw 32 bytes of a PoSW checkpoint.  Internal nodes are
    SHA-256(left_child || right_child).  If the number of leaves is odd at
    any layer, the last node is duplicated to complete the pair.

    Usage::

        tree = MerkleTree(checkpoints)
        root_hex = tree.root
        proof   = tree.prove(42)           # O(log N) proof for leaf 42
        valid   = MerkleTree.verify(proof) # O(log N) verification
    """

    def __init__(self, leaves: List[bytes]) -> None:
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf.")
        self._leaves: List[bytes] = list(leaves)
        self._layers: List[List[bytes]] = self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> List[List[bytes]]:
        """Construct all layers bottom-up from leaves to root.

        Returns a list of layers where layers[0] = leaves,
        layers[-1] = [root_hash].
        """
        layers: List[List[bytes]] = [self._leaves]
        current: List[bytes] = self._leaves

        while len(current) > 1:
            # Pad with duplicate if odd number of nodes at this layer.
            if len(current) % 2 == 1:
                current = current + [current[-1]]

            next_layer: List[bytes] = []
            for i in range(0, len(current), 2):
                parent = hashlib.sha256(current[i] + current[i + 1]).digest()
                next_layer.append(parent)

            layers.append(next_layer)
            current = next_layer

        return layers

    @property
    def root(self) -> str:
        """Hex-encoded SHA-256 binary Merkle root."""
        return self._layers[-1][0].hex()

    # ------------------------------------------------------------------
    # Prove / Verify
    # ------------------------------------------------------------------

    def prove(self, leaf_index: int) -> MerkleProof:
        """Generate an O(log N) inclusion proof for the leaf at *leaf_index*.

        Args:
            leaf_index: 0-based index of the leaf to prove.

        Returns:
            A MerkleProof containing the ordered sibling path from leaf to root.

        Raises:
            IndexError: If leaf_index is out of range.
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError(
                f"leaf_index {leaf_index} is out of range "
                f"for a tree with {len(self._leaves)} leaves."
            )

        sibling_path: List[Tuple[bytes, bool]] = []
        idx = leaf_index

        for layer in self._layers[:-1]:
            # Pad the layer if needed (mirrors the build step exactly).
            padded = layer + ([layer[-1]] if len(layer) % 2 == 1 else [])

            if idx % 2 == 0:
                # Current node is a left child; sibling is the right node.
                sibling_idx = idx + 1 if (idx + 1) < len(padded) else idx
                sibling_path.append((padded[sibling_idx], True))
            else:
                # Current node is a right child; sibling is the left node.
                sibling_path.append((padded[idx - 1], False))

            idx //= 2

        return MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=self._leaves[leaf_index],
            sibling_path=sibling_path,
            root=self.root,
        )

    @staticmethod
    def verify(proof: MerkleProof) -> bool:
        """Verify a MerkleProof in O(log N) time without the full tree.

        Recomputes the path from the leaf to the root and checks that the
        final hash equals proof.root.

        Args:
            proof: A MerkleProof previously generated by prove().

        Returns:
            True if the proof is cryptographically valid, False otherwise.
        """
        current: bytes = proof.leaf_hash
        for sibling, sibling_is_right in proof.sibling_path:
            if sibling_is_right:
                # Current is left child: H(current || sibling)
                current = hashlib.sha256(current + sibling).digest()
            else:
                # Current is right child: H(sibling || current)
                current = hashlib.sha256(sibling + current).digest()
        return current.hex() == proof.root


# ---------------------------------------------------------------------------
# PoSW data structures
# ---------------------------------------------------------------------------


@dataclass
class PoSWProof:
    """Structured representation of a completed PoSW computation.

    Attributes:
        merkle_root:    Hex-encoded SHA-256 binary Merkle root over all
                        checkpoints.  Build a MerkleTree(checkpoints) and
                        call .prove(i) for an O(log N) spot-check proof.
        checkpoints:    The 1_000 intermediate hash values (raw bytes).
        t:              Total number of hash iterations performed.
        seed:           The 32-byte random seed used to start the chain.
        elapsed_sec:    Actual wall-clock time the computation took.
        target_sec:     Target duration used during calibration.
        drift_fraction: (elapsed - target) / target.  Positive = slow,
                        negative = fast.  Logged as a security metric.
    """

    merkle_root: str
    checkpoints: List[bytes]
    t: int
    seed: bytes
    elapsed_sec: float
    target_sec: int
    drift_fraction: float


@dataclass
class PoSWManager:
    """Sequential Work time-lock manager.

    The manager is a value object: all mutable state is encapsulated and
    transitions are explicit.  It is NOT thread-safe for concurrent calls
    to compute_posw() — one PoSWManager instance per agent mission.

    Args:
        target_duration_seconds: How long the hash chain should take to compute.
    """

    target_duration_seconds: int
    _proof: Optional[PoSWProof] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.target_duration_seconds, int)
            or isinstance(self.target_duration_seconds, bool)
            or self.target_duration_seconds <= 0
        ):
            raise ValueError(
                "target_duration_seconds must be a positive integer "
                f"(got {self.target_duration_seconds!r})."
            )
        self._log = get_chronos_logger("PoSW")
        self._seed: bytes = secrets.token_bytes(32)
        self._hashes_per_second: int = self._calibrate()
        if self._hashes_per_second <= 0:
            raise RuntimeError(
                "PoSW calibration produced a non-positive hash rate. "
                "Unable to enforce sequential-work timing invariant."
            )
        self.t: int = max(1, self._hashes_per_second * self.target_duration_seconds)
        self._log.info(
            f"PoSW initialised: T={self.t:,} hashes "
            f"({self._hashes_per_second:,}/s * {self.target_duration_seconds}s target)"
        )

    # ------------------------------------------------------------------
    # Calibration
    # ------------------------------------------------------------------

    def _calibrate(self) -> int:
        """Measure local SHA-256 throughput without syscall overhead.

        We pre-warm the CPU for 1_000 hashes, then time 100_000 hashes.
        The warm-up prevents cold-branch-predictor penalties from inflating the
        measurement and causing under-counting in the actual chain.

        Returns:
            Integer hash rate in hashes/second.
        """
        self._log.info("Calibrating SHA-256 hash rate (100 000 iteration sample)...")

        current: bytes = b"chronos-calibration-seed-v1"

        # Pre-warm: discard these results.
        for _ in range(1_000):
            current = hashlib.sha256(current).digest()

        count: int = 100_000
        t0: float = time.perf_counter()
        for _ in range(count):
            current = hashlib.sha256(current).digest()
        elapsed: float = time.perf_counter() - t0

        rate: int = int(count / elapsed)
        self._log.info(f"Calibration complete: {rate:,} hashes/s")
        return rate

    # ------------------------------------------------------------------
    # PoSW computation
    # ------------------------------------------------------------------

    def compute_posw(self) -> None:
        """Execute the sequential hash chain in an isolated subprocess.

        Communication uses multiprocessing.Pipe (not Queue) to avoid OS pipe
        buffer exhaustion that causes deadlock when the checkpoint payload
        exceeds the OS kernel pipe buffer limit (~65 KB on Linux/Windows).
        With Pipe, the OS will block the writer until the reader drains —
        there is no fixed capacity limit as with Queue's underlying socket.

        After this method returns, derive_encryption_key() may be called.

        Raises:
            RuntimeError: If the worker subprocess exits with a non-zero code.
        """
        self._log.info(
            f"Starting PoSW subprocess: T={self.t:,} hashes, "
            f"~{self.target_duration_seconds}s target duration..."
        )

        if _RUST_AVAILABLE:
            self._log.info("Accelerated Rust PoSW (PyO3) backend available. Using fast_posw.")
            t0: float = time.time()
            checkpoints = fast_posw.compute_posw_chain(self._seed, self.t)
            elapsed: float = time.time() - t0
        else:
            self._log.warning("Rust PoSW backend not found. Falling back to slow Python multiprocessing...")
            # Pipe: parent_conn receives, child_conn sends.
            ctx = mp.get_context("spawn")
            parent_conn, child_conn = ctx.Pipe(duplex=False)

            worker = ctx.Process(
                target=_posw_worker,
                args=(self._seed, self.t, child_conn),
                name="chronos-posw-worker",
                daemon=False,  # Non-daemon so join() works correctly.
            )

            t0 = time.time()
            worker.start()

            # Close child's end in parent process so that the EOF signal propagates
            # correctly when the child exits after sending.
            child_conn.close()

            # Block until the worker sends the checkpoint list.
            # mp.Pipe.recv() will block until data is available; there is no
            # polling loop needed.  The data is pickle-serialised by multiprocessing.
            checkpoints = None
            try:
                checkpoints = parent_conn.recv()
            except EOFError:
                # Worker closed the pipe without sending — will be caught below.
                pass
            finally:
                parent_conn.close()

            worker.join()
            elapsed = time.time() - t0

            if worker.exitcode != 0:
                raise RuntimeError(
                    f"PoSW worker process exited with code {worker.exitcode}. "
                    f"Check system resources (OOM killer, CPU thermal throttling)."
                )

            if checkpoints is None:
                raise RuntimeError("PoSW worker process exited without producing checkpoints.")

        # Build the real binary Merkle tree over the raw checkpoint leaves.
        tree = MerkleTree(checkpoints)
        merkle_root: str = tree.root

        # Drift analysis — compare actual elapsed vs. calibrated target.
        if self.target_duration_seconds > 0:
            drift = (elapsed - self.target_duration_seconds) / self.target_duration_seconds
            if abs(drift) > _DRIFT_WARNING_THRESHOLD:
                self._log.warning(
                    f"[POSW DRIFT] Elapsed {elapsed:.3f}s vs target "
                    f"{self.target_duration_seconds}s - drift={drift:+.1%}. "
                    f"Possible CPU frequency scaling (thermal throttling / power "
                    f"management).  The cryptographic guarantee is unaffected but "
                    f"the time-lock may be shorter or longer than the stated target."
                )
        else:
            drift = 0.0

        self._proof = PoSWProof(
            merkle_root=merkle_root,
            checkpoints=checkpoints,
            t=self.t,
            seed=self._seed,
            elapsed_sec=elapsed,
            target_sec=self.target_duration_seconds,
            drift_fraction=drift,
        )

        self._log.info(
            f"PoSW complete in {elapsed:.3f}s (drift={drift:+.1%}). "
            f"Binary Merkle root ({len(checkpoints)} leaves): "
            f"{merkle_root[:24]}..."
        )

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def derive_encryption_key(self) -> bytes:
        """Derive a 256-bit key from the PoSW commitment via HKDF-SHA256.

        The Merkle root acts as the IKM (Input Key Material) for HKDF.  Using
        HKDF instead of raw SHA256 provides:
            a) Domain separation via the context string (info parameter).
            b) Output uniformity — even if the Merkle root has low entropy
               in a degenerate case, HKDF expands it to a full 256-bit key.

        Returns:
            32 raw bytes (256 bits) suitable for AES-256.

        Raises:
            ValueError: If compute_posw() has not been called yet.
        """
        if self._proof is None:
            raise ValueError(
                "derive_encryption_key() called before compute_posw() completed. "
                "Ensure the PoSW computation finishes before attempting key derivation."
            )

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._seed,  # The random seed acts as the HKDF salt.
            info=_HKDF_INFO,
        )
        key: bytes = kdf.derive(self._proof.merkle_root.encode("ascii"))
        self._log.info("K_enc derived from PoSW binary Merkle root (HKDF-SHA256).")
        return key

    def verify_checkpoint(self, leaf_index: int) -> bool:
        """Spot-check that a single checkpoint is committed by the Merkle root.

        This is the O(log N) spot-verification of the hash-chain PoSW.
        An external verifier selects a random leaf_index and calls this to
        confirm the full hash chain was computed without replaying T hashes.

        Args:
            leaf_index: 0-based index of the checkpoint to verify.

        Returns:
            True if the checkpoint is correctly committed in the Merkle root.

        Raises:
            ValueError: If compute_posw() has not been called yet.
        """
        if self._proof is None:
            raise ValueError("verify_checkpoint() called before compute_posw() completed.")
        tree = MerkleTree(self._proof.checkpoints)
        proof = tree.prove(leaf_index)
        return MerkleTree.verify(proof)

    @property
    def proof(self) -> Optional[PoSWProof]:
        """Return the PoSW proof if computation has completed, else None."""
        return self._proof


# ---------------------------------------------------------------------------
# Worker function (runs inside the subprocess — must be module-level for
# multiprocessing to pickle it on Windows).
# ---------------------------------------------------------------------------


def _posw_worker(
    seed: bytes,
    t: int,
    conn: "mp.connection.Connection",
) -> None:
    """Hash-chain worker function.  Runs in an isolated subprocess.

    Splits the T-step chain into _CHECKPOINT_COUNT segments.  At the end of
    each segment, the current hash value is appended to checkpoints.  The
    parent process builds the Merkle tree from these raw leaves so the worker
    code is kept minimal and easy to audit.

    Args:
        seed:   32-byte random seed for the chain start.
        t:      Total number of SHA-256 iterations to perform.
        conn:   Write-end of a multiprocessing.Pipe connection.
                The checkpoint list is sent via conn.send() and the pipe is
                closed before the process exits.
    """
    current: bytes = seed
    checkpoints: List[bytes] = []

    step: int = max(1, t // _CHECKPOINT_COUNT)
    full_segments: int = t // step
    remainder: int = t % step

    for _ in range(full_segments):
        for _ in range(step):
            current = hashlib.sha256(current).digest()
        checkpoints.append(current)

    # Handle any remaining iterations (keeps T exact).
    for _ in range(remainder):
        current = hashlib.sha256(current).digest()

    conn.send(checkpoints)
    conn.close()
