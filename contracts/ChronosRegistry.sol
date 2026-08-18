// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title CHRONOS erasure attestation registry
/// @notice Public, append-only record of verified erasure attestations. Replaces
///         "ask the operator whether the agent wiped" with "check the chain".
///
/// @dev SCOPE — read `Groth16Verifier.sol` before citing an entry here as a
///      containment guarantee. A stored attestation proves that, at `attestedAt`,
///      someone submitted a proof satisfying the erasure circuit for the recorded
///      commitments under the deployed verifying key. The load-bearing caveat is
///      that the trusted setup is presently single-party, so the setup operator can
///      mint proofs that verify here.
///
///      What this adds unconditionally: immutability, public timestamps, replay
///      resistance per mission, and an audit trail nobody can quietly revise.
contract ChronosRegistry {
    /// @notice One verified erasure attestation.
    ///
    /// @dev The five circuit public inputs are stored in full rather than hashed
    ///      together. An earlier revision stored two single-byte values, which was
    ///      all the circuit bound at the time; storing the full commitments means a
    ///      verifier can check an entry against a published `mission_public.json`
    ///      field by field, and can tell *which* mission an entry refers to without
    ///      trusting the `missionId` key.
    struct Attestation {
        /// Block timestamp at which the proof was accepted.
        uint64 attestedAt;
        /// Address that submitted the proof. Informational only — the proof, not
        /// the sender, is what carries weight.
        address attester;
        /// Poseidon commitment to the VDF output.
        uint256 yCommit;
        /// Commitment to the time-locked ciphertext.
        uint256 ctCommit;
        /// Commitment to the plaintext secret key, fixed by the provisioner.
        uint256 skCommit;
        /// Commitment to the mission identifier.
        uint256 missionCommit;
        /// Commitment to the containment summary. Constrained in-circuit to
        /// describe a run that terminated erased with all capabilities revoked.
        uint256 containmentCommit;
    }

    /// @notice Immutable verifier. A new trusted setup means a new registry.
    Groth16Verifier public immutable verifier;

    /// @dev missionId => attestation. `attestedAt == 0` means not yet attested.
    mapping(bytes32 => Attestation) private _attestations;

    /// @notice Total attestations recorded, for cheap off-chain enumeration.
    uint256 public attestationCount;

    event ErasureAttested(
        bytes32 indexed missionId,
        address indexed attester,
        uint256 yCommit,
        uint256 skCommit,
        uint256 containmentCommit,
        uint64 attestedAt
    );

    error AlreadyAttested(bytes32 missionId);
    error InvalidProof(bytes32 missionId);
    error EmptyMissionId();

    constructor(Groth16Verifier _verifier) {
        require(address(_verifier) != address(0), "Registry: verifier is zero");
        verifier = _verifier;
    }

    /// @notice Verify an erasure proof and record it permanently.
    ///
    /// @dev Reverts rather than returning false, so a failed attestation cannot be
    ///      mistaken for a successful one by a caller ignoring return values. One
    ///      attestation per `missionId`: a mission erases once, and allowing
    ///      overwrites would let an operator replace an inconvenient record.
    ///
    /// @param missionId  Mission identifier, typically SHA-256 of the mission string.
    /// @param input      The five circuit public inputs, in ABI order.
    /// @param proofA     Groth16 A, as [x, y].
    /// @param proofB     Groth16 B, as [[x.c1, x.c0], [y.c1, y.c0]].
    /// @param proofC     Groth16 C, as [x, y].
    function attestErasure(
        bytes32 missionId,
        uint256[5] calldata input,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        if (missionId == bytes32(0)) revert EmptyMissionId();
        if (_attestations[missionId].attestedAt != 0) {
            revert AlreadyAttested(missionId);
        }

        if (!verifier.verifyProof(proofA, proofB, proofC, input)) {
            revert InvalidProof(missionId);
        }

        uint64 now64 = uint64(block.timestamp);
        _attestations[missionId] = Attestation({
            attestedAt: now64,
            attester: msg.sender,
            yCommit: input[0],
            ctCommit: input[1],
            skCommit: input[2],
            missionCommit: input[3],
            containmentCommit: input[4]
        });
        attestationCount += 1;

        emit ErasureAttested(
            missionId,
            msg.sender,
            input[0],
            input[2],
            input[4],
            now64
        );
    }

    /// @notice Whether a mission has a recorded erasure attestation.
    function isAttested(bytes32 missionId) external view returns (bool) {
        return _attestations[missionId].attestedAt != 0;
    }

    /// @notice Retrieve a stored attestation.
    /// @dev Returns a zeroed struct when absent; check `attestedAt != 0`.
    function getAttestation(bytes32 missionId)
        external
        view
        returns (Attestation memory)
    {
        return _attestations[missionId];
    }

    /// @notice Verify a proof without recording it. Useful for dry runs before
    ///         spending gas on a transaction that would revert.
    function checkProof(
        uint256[5] calldata input,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external view returns (bool) {
        return verifier.verifyProof(proofA, proofB, proofC, input);
    }
}
