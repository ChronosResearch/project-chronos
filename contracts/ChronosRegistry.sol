// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title CHRONOS erasure attestation registry
/// @notice Public, append-only record of verified erasure attestations. Replaces
///         "ask the agent's operator whether it wiped" with "check the chain".
///
/// @dev SCOPE — read this before citing the contract as a containment guarantee.
///
///      A stored attestation proves that, at `attestedAt`, someone submitted a
///      Groth16 proof that satisfied the erasure circuit for `(yFirstByte,
///      wipePattern)` under the deployed verifying key.
///
///      It does not prove the agent was contained. The known gaps are documented
///      in `Groth16Verifier.sol`; the load-bearing one is that CHRONOS's trusted
///      setup is presently single-party, so the setup operator can mint proofs
///      that verify here. On-chain publication removes the need to trust the
///      *operator's claim*; it does not remove the need to trust the *ceremony*.
///
///      What it does provide, unconditionally: immutability, public timestamps,
///      replay resistance per mission, and an audit trail nobody can quietly
///      revise after the fact. That is worth having on its own.
contract ChronosRegistry {
    /// @notice One verified erasure attestation.
    struct Attestation {
        /// Block timestamp at which the proof was accepted.
        uint64 attestedAt;
        /// First byte of the VDF output, bound as a circuit public input.
        uint8 yFirstByte;
        /// Declared post-wipe byte value (0xFF for CHRONOS's triple-pass wipe).
        uint8 wipePattern;
        /// Address that submitted the proof. Informational only — the proof,
        /// not the sender, is what carries weight.
        address attester;
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
        uint8 yFirstByte,
        uint8 wipePattern,
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
    /// @dev Reverts rather than returning false, so a failed attestation cannot
    ///      be mistaken for a successful one by a caller ignoring return values.
    ///      One attestation per `missionId`: a mission erases once, and allowing
    ///      overwrites would let an operator replace an inconvenient record.
    ///
    /// @param missionId    Mission identifier, typically SHA-256 of the mission string.
    /// @param yFirstByte   Public input 1 — first byte of the VDF output.
    /// @param wipePattern  Public input 2 — declared post-wipe byte.
    /// @param proofA       Groth16 A, as [x, y].
    /// @param proofB       Groth16 B, as [[x.c1, x.c0], [y.c1, y.c0]].
    /// @param proofC       Groth16 C, as [x, y].
    function attestErasure(
        bytes32 missionId,
        uint8 yFirstByte,
        uint8 wipePattern,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        if (missionId == bytes32(0)) revert EmptyMissionId();
        if (_attestations[missionId].attestedAt != 0) {
            revert AlreadyAttested(missionId);
        }

        uint256[2] memory publicInputs;
        publicInputs[0] = uint256(yFirstByte);
        publicInputs[1] = uint256(wipePattern);

        if (!verifier.verifyProof(proofA, proofB, proofC, publicInputs)) {
            revert InvalidProof(missionId);
        }

        uint64 now64 = uint64(block.timestamp);
        _attestations[missionId] = Attestation({
            attestedAt: now64,
            yFirstByte: yFirstByte,
            wipePattern: wipePattern,
            attester: msg.sender
        });
        attestationCount += 1;

        emit ErasureAttested(missionId, msg.sender, yFirstByte, wipePattern, now64);
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

    /// @notice Verify a proof without recording it. Useful for dry runs.
    function checkProof(
        uint8 yFirstByte,
        uint8 wipePattern,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external view returns (bool) {
        uint256[2] memory publicInputs;
        publicInputs[0] = uint256(yFirstByte);
        publicInputs[1] = uint256(wipePattern);
        return verifier.verifyProof(proofA, proofB, proofC, publicInputs);
    }
}
