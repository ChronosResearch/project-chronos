// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

/// @title Groth16 verifier for the CHRONOS erasure circuit
/// @notice Verifies BN254 Groth16 proofs on-chain using the EVM's alt_bn128
///         precompiles. BN254 is the same curve as alt_bn128, which is why the
///         circuit targets it — proofs are checkable by any Ethereum node with
///         no trusted relayer.
///
/// @dev WHAT AN ACCEPTED PROOF DOES AND DOES NOT MEAN
///
///      Accepted means: someone knew a witness satisfying the erasure circuit
///      for the supplied public inputs, under this contract's verifying key.
///      Concretely, that all 32 bytes of a key buffer held the declared wipe
///      pattern, and that the prover's VDF output byte matched the claimed one.
///
///      It does NOT mean the agent was contained. Three specific gaps:
///
///      1. The CHRONOS Groth16 trusted setup is currently single-party — one
///         machine XOR-folds three local RNGs, so whoever ran setup holds the
///         trapdoor and can forge proofs that verify here perfectly. Until a
///         real Powers-of-Tau ceremony replaces it, on-chain acceptance is
///         conditional on trusting the setup operator.
///      2. The circuit binds a *prover-supplied* buffer. It proves a buffer was
///         zeroized, not that the live key was.
///      3. Ciphertext decryption is not encoded in-circuit, so the wiped buffer
///         is not tied to the time-locked ciphertext.
///
///      This contract makes attestation publicly auditable. It does not upgrade
///      the underlying cryptographic claim.
library Pairing {
    /// @dev BN254 base field modulus.
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    /// @dev Fp2 coordinates are stored as [c1, c0] — imaginary part FIRST.
    ///      This matches the alt_bn128 precompile's expected encoding and is the
    ///      reverse of arkworks' native (c0, c1) ordering. `solidity.rs` performs
    ///      the swap on export. Getting this backwards produces a verifier that
    ///      rejects every valid proof.
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /// @notice Additive inverse of a G1 point.
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    }

    /// @notice G1 addition via the 0x06 precompile.
    function addition(G1Point memory p1, G1Point memory p2)
        internal
        view
        returns (G1Point memory r)
    {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;

        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }
        require(success, "Pairing: G1 addition failed");
    }

    /// @notice G1 scalar multiplication via the 0x07 precompile.
    function scalarMul(G1Point memory p, uint256 s)
        internal
        view
        returns (G1Point memory r)
    {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;

        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 0x07, input, 0x60, r, 0x40)
        }
        require(success, "Pairing: G1 scalar mul failed");
    }

    /// @notice Checks whether the product of four pairings equals one, via the
    ///         0x08 precompile.
    function pairingCheck4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        uint256[24] memory input;

        _fill(input, 0, a1, a2);
        _fill(input, 6, b1, b2);
        _fill(input, 12, c1, c2);
        _fill(input, 18, d1, d2);

        uint256[1] memory out;
        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 0x08, input, 0x300, out, 0x20)
        }
        require(success, "Pairing: pairing check failed");
        return out[0] == 1;
    }

    function _fill(
        uint256[24] memory input,
        uint256 offset,
        G1Point memory g1,
        G2Point memory g2
    ) private pure {
        input[offset + 0] = g1.X;
        input[offset + 1] = g1.Y;
        input[offset + 2] = g2.X[0];
        input[offset + 3] = g2.X[1];
        input[offset + 4] = g2.Y[0];
        input[offset + 5] = g2.Y[1];
    }
}

/// @title CHRONOS Groth16 verifier
/// @notice Verifying key is injected at construction so the same bytecode can
///         serve a re-run trusted setup. `chronos-snark`'s `solidity.rs`
///         generates the constructor arguments — see `export_verifying_key`.
contract Groth16Verifier {
    using Pairing for Pairing.G1Point;
    using Pairing for Pairing.G2Point;

    /// @dev BN254 scalar field order. Public inputs must be strictly less than
    ///      this, otherwise the proof is trivially malleable.
    uint256 public constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev The erasure circuit exposes exactly two public inputs, in this
    ///      order: y[0] then WIPE_PATTERN. Changing the circuit's public input
    ///      layout requires redeploying with a new key.
    uint256 public constant PUBLIC_INPUT_COUNT = 2;

    Pairing.G1Point internal alpha;
    Pairing.G2Point internal beta;
    Pairing.G2Point internal gamma;
    Pairing.G2Point internal delta;

    /// @dev IC.length must equal PUBLIC_INPUT_COUNT + 1.
    Pairing.G1Point[] internal ic;

    constructor(
        uint256[2] memory _alpha,
        uint256[2][2] memory _beta,
        uint256[2][2] memory _gamma,
        uint256[2][2] memory _delta,
        uint256[2][] memory _ic
    ) {
        require(
            _ic.length == PUBLIC_INPUT_COUNT + 1,
            "Verifier: IC length must be public inputs + 1"
        );

        alpha = Pairing.G1Point(_alpha[0], _alpha[1]);
        beta = Pairing.G2Point(_beta[0], _beta[1]);
        gamma = Pairing.G2Point(_gamma[0], _gamma[1]);
        delta = Pairing.G2Point(_delta[0], _delta[1]);

        for (uint256 i = 0; i < _ic.length; i++) {
            ic.push(Pairing.G1Point(_ic[i][0], _ic[i][1]));
        }
    }

    /// @notice Verify a Groth16 proof against the supplied public inputs.
    /// @param proofA  Proof element A, as [x, y].
    /// @param proofB  Proof element B, as [[x.c1, x.c0], [y.c1, y.c0]].
    /// @param proofC  Proof element C, as [x, y].
    /// @param input   Public inputs: [y[0], wipePattern].
    /// @return True iff the pairing check succeeds.
    function verifyProof(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[PUBLIC_INPUT_COUNT] calldata input
    ) public view returns (bool) {
        for (uint256 i = 0; i < PUBLIC_INPUT_COUNT; i++) {
            require(input[i] < SCALAR_FIELD, "Verifier: input >= scalar field");
        }

        // vk_x = IC[0] + sum_i input[i] * IC[i+1]
        Pairing.G1Point memory vkX = ic[0];
        for (uint256 i = 0; i < PUBLIC_INPUT_COUNT; i++) {
            vkX = Pairing.addition(vkX, Pairing.scalarMul(ic[i + 1], input[i]));
        }

        Pairing.G1Point memory a = Pairing.G1Point(proofA[0], proofA[1]);
        Pairing.G2Point memory b = Pairing.G2Point(proofB[0], proofB[1]);
        Pairing.G1Point memory c = Pairing.G1Point(proofC[0], proofC[1]);

        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        return
            Pairing.pairingCheck4(
                Pairing.negate(a),
                b,
                alpha,
                beta,
                vkX,
                gamma,
                c,
                delta
            );
    }
}
