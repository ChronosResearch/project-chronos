//! Operator correction grants — unforgeable, single-use, amount-bound.
//!
//! # The hole this closes
//!
//! A6 lets the agent resolve accumulated uncertainty by recording a
//! [`Event::HumanCorrection`](crate::containment::Event::HumanCorrection). In the
//! first cut of A6 that event carried nothing but an amount, so the agent could
//! issue its own corrections: accumulate uncertainty to the threshold, self-emit a
//! correction resolving all of it, and continue indefinitely. The axiom held on
//! paper while the mechanism it was meant to enforce did not exist. An
//! interruptibility claim in which the interrupted party signs its own release
//! form is not a claim.
//!
//! The asymmetry needed is the one the rest of CHRONOS already relies on: the
//! agent must be able to *check* an authorisation without being able to *produce*
//! one. Public-key signatures give that, but adding a signature scheme to the
//! containment core is a large dependency for a one-bit decision, and the
//! containment monitor is deliberately free of the SNARK and network stacks. A
//! reverse hash chain gives the same asymmetry from preimage resistance alone.
//!
//! # Construction
//!
//! The provisioner picks a random token and an intended resolution amount for each
//! correction it is willing to authorise, then chains them back to front:
//!
//! ```text
//! link_{N+1} = CHAIN_END
//! link_i     = H(DOMAIN || token_i || amount_i || link_{i+1})
//! anchor     = link_1                                    (published)
//! ```
//!
//! `anchor` ships in the mission artifact beside the other commitments. To
//! authorise the `i`-th correction the operator reveals
//! `(token_i, amount_i, link_{i+1})`. The monitor recomputes the link, compares it
//! against the anchor it currently holds, and on a match admits the correction and
//! advances the anchor to `link_{i+1}`.
//!
//! Four properties follow, and each is load-bearing:
//!
//! | Property | Why it holds |
//! |---|---|
//! | **Unforgeable** | advancing requires a SHA-256 preimage of the current anchor |
//! | **Amount-bound** | `amount_i` is hashed into `link_i`, so a genuine grant cannot be inflated |
//! | **Single-use** | the anchor advances on use, so a replayed grant no longer matches |
//! | **Ordered** | grant `i+1` is only checkable once grant `i` is spent |
//!
//! Single-use is not incidental. Without it one legitimate grant could be replayed
//! to resolve unbounded uncertainty, which is the same hole as forgery reached by a
//! different route.
//!
//! The chain length also caps total resolvable uncertainty at the sum of the
//! amounts, fixed before the mission starts. The operator therefore bounds in
//! advance how much doubt it is willing to absolve, which is the quantity an
//! auditor cares about.
//!
//! # What this does and does not establish
//!
//! It establishes that an admitted correction was authorised by whoever holds the
//! seed, and that its amount is the authorised one.
//!
//! It does not establish that a human considered the request; the operator can
//! script the reveals. That is deliberate. CHRONOS's threat model separates the
//! provisioner from the agent, and the property being secured is that *the agent
//! did not authorise itself*. Whether the authorising party exercised judgement is
//! outside anything cryptography can see.
//!
//! It also inherits `F_HONEST-UNCERTAINTY`: a correction is authorised against a
//! *self-reported* uncertainty figure. Closing that is a separate problem — it
//! requires moving the uncertainty estimator itself across the trust boundary.

use sha2::{Digest, Sha256};

/// Domain tag for chain links, so a link cannot be confused with the ledger chain
/// digest or any other SHA-256 value in the system.
const DOMAIN: &[u8] = b"chronos-correction-chain-v1";

/// Terminal link. Reaching it means every authorised correction is spent.
///
/// All-zero is safe as a sentinel: a grant whose link equalled it would be a
/// SHA-256 preimage break, so the agent cannot manufacture one, and no grant can
/// authorise against an exhausted chain.
pub const CHAIN_END: [u8; 32] = [0u8; 32];

/// One operator-authorised correction, as revealed to the agent.
///
/// `Copy` so [`Event`](crate::containment::Event) stays `Copy` and the monitor
/// keeps its by-value shape with no interior mutability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionGrant {
    /// Revealed preimage token for this position in the chain.
    pub token: [u8; 32],
    /// Uncertainty this grant resolves. Bound into the link, so it cannot be
    /// altered without breaking the hash.
    pub amount: u64,
    /// The anchor the monitor advances to once this grant is consumed.
    pub next_anchor: [u8; 32],
}

impl CorrectionGrant {
    /// The link this grant hashes to. Equals the anchor it is valid against.
    #[must_use]
    pub fn link(&self) -> [u8; 32] {
        link(&self.token, self.amount, &self.next_anchor)
    }

    /// Whether this grant authorises a correction against `anchor`.
    ///
    /// Comparison is a plain `==`. Constant-time comparison buys nothing here:
    /// the anchor is public, the attacker already knows it, and the secret is the
    /// preimage, which timing does not reveal.
    #[must_use]
    pub fn authorises(&self, anchor: &[u8; 32]) -> bool {
        // An exhausted chain authorises nothing. Checked explicitly rather than
        // relying on preimage resistance, so the refusal is a stated rule instead
        // of an emergent one.
        if *anchor == CHAIN_END {
            return false;
        }
        self.link() == *anchor
    }
}

/// Compute a chain link from its components.
#[must_use]
pub fn link(token: &[u8; 32], amount: u64, next_anchor: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(token);
    h.update(amount.to_be_bytes());
    h.update(next_anchor);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Build a correction chain from operator-chosen tokens and amounts.
///
/// Returns the anchor to publish and the grants in the order they must be
/// revealed. This is a provisioner-side helper: the agent never calls it, because
/// calling it is precisely the capability the agent must not have.
///
/// An empty input yields [`CHAIN_END`] and no grants — a mission in which no
/// correction is ever authorised, so the agent must halt at the threshold rather
/// than resolve its way past it.
#[must_use]
pub fn build_chain(tokens_and_amounts: &[([u8; 32], u64)]) -> ([u8; 32], Vec<CorrectionGrant>) {
    let mut grants: Vec<CorrectionGrant> = Vec::with_capacity(tokens_and_amounts.len());
    let mut next = CHAIN_END;

    // Built back to front: link_i commits to link_{i+1}, so the last grant is the
    // one that can be constructed first.
    for &(token, amount) in tokens_and_amounts.iter().rev() {
        let grant = CorrectionGrant {
            token,
            amount,
            next_anchor: next,
        };
        next = grant.link();
        grants.push(grant);
    }

    grants.reverse();
    (next, grants)
}

/// A fixed two-grant chain for the startup model checker.
///
/// [`verify_axioms`](crate::containment::verify_axioms) needs concrete values to
/// exercise both branches of the authorisation check, and hash preimages do not
/// survive the interval abstraction the other axioms use. Returning a real chain
/// plus a deliberately invalid grant lets A7 be checked over the abstraction
/// rather than asserted.
///
/// Returns `(anchor, valid_grant, forged_grant)`.
#[must_use]
pub fn model_check_chain() -> ([u8; 32], CorrectionGrant, CorrectionGrant) {
    let (anchor, grants) = build_chain(&[([0x11u8; 32], 1), ([0x22u8; 32], 1)]);
    let forged = CorrectionGrant {
        token: [0xAAu8; 32],
        amount: 1,
        next_anchor: [0xBBu8; 32],
    };
    (anchor, grants[0], forged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// The headline property: grants authorise in order, each exactly once, and
    /// the chain terminates.
    #[test]
    fn test_chain_authorises_in_order() {
        let (anchor, grants) = build_chain(&[(tok(1), 10), (tok(2), 20), (tok(3), 30)]);
        assert_eq!(grants.len(), 3);

        let mut current = anchor;
        for (i, g) in grants.iter().enumerate() {
            assert!(
                g.authorises(&current),
                "grant {i} must authorise against the anchor it follows"
            );
            current = g.next_anchor;
        }
        assert_eq!(current, CHAIN_END, "the chain must terminate at CHAIN_END");
    }

    /// Out-of-order reveal fails: grant 2 is not checkable until grant 1 is spent.
    #[test]
    fn test_out_of_order_grant_is_rejected() {
        let (anchor, grants) = build_chain(&[(tok(1), 10), (tok(2), 20)]);
        assert!(grants[0].authorises(&anchor));
        assert!(
            !grants[1].authorises(&anchor),
            "a later grant must not be usable before its predecessor"
        );
    }

    /// Replay fails: once the anchor advances, the spent grant no longer matches.
    #[test]
    fn test_replay_is_rejected() {
        let (_, grants) = build_chain(&[(tok(1), 10), (tok(2), 20)]);
        let advanced = grants[0].next_anchor;
        assert!(
            !grants[0].authorises(&advanced),
            "a spent grant must not authorise again"
        );
        assert!(
            grants[1].authorises(&advanced),
            "but its successor must, or the chain cannot progress"
        );
    }

    /// The forgery this module exists to prevent: inflating the amount on an
    /// otherwise genuine grant.
    #[test]
    fn test_amount_is_bound_into_the_link() {
        let (anchor, grants) = build_chain(&[(tok(1), 10)]);
        for bad in [0u64, 9, 11, u64::MAX] {
            let mut inflated = grants[0];
            inflated.amount = bad;
            assert!(
                !inflated.authorises(&anchor),
                "amount {bad} must invalidate a grant authorised for 10"
            );
        }
    }

    /// A grant the agent invented cannot authorise without a preimage.
    #[test]
    fn test_fabricated_grant_is_rejected() {
        let (anchor, _) = build_chain(&[(tok(1), 10)]);
        let forged = CorrectionGrant {
            token: tok(0xAA),
            amount: 10,
            next_anchor: tok(0xBB),
        };
        assert!(!forged.authorises(&anchor));
    }

    /// Redirecting a genuine grant to an attacker-chosen successor fails, so the
    /// agent cannot splice in a chain it controls.
    #[test]
    fn test_next_anchor_cannot_be_substituted() {
        let (anchor, grants) = build_chain(&[(tok(1), 10), (tok(2), 20)]);
        let mut spliced = grants[0];
        spliced.next_anchor = link(&tok(0xEE), u64::MAX, &CHAIN_END);
        assert!(!spliced.authorises(&anchor));
    }

    /// An exhausted chain authorises nothing, including a grant that hashes to the
    /// sentinel.
    #[test]
    fn test_exhausted_chain_authorises_nothing() {
        let (_, grants) = build_chain(&[(tok(1), 10)]);
        assert_eq!(grants[0].next_anchor, CHAIN_END, "single-grant chain ends immediately");
        assert!(
            !grants[0].authorises(&CHAIN_END),
            "no grant may authorise against the terminal sentinel"
        );
    }

    /// The final grant of a chain must still be usable, or the last authorisation
    /// the operator paid for is unspendable.
    #[test]
    fn test_final_grant_is_usable() {
        let (anchor, grants) = build_chain(&[(tok(1), 7)]);
        assert!(grants[0].authorises(&anchor));
        assert_eq!(grants[0].amount, 7);
    }

    /// An empty grant list authorises nothing at all.
    #[test]
    fn test_empty_chain_grants_nothing() {
        let (anchor, grants) = build_chain(&[]);
        assert_eq!(anchor, CHAIN_END);
        assert!(grants.is_empty());
    }

    /// Every component must affect the anchor, or two missions could share a chain.
    #[test]
    fn test_anchor_depends_on_every_component() {
        let (a, _) = build_chain(&[(tok(1), 10)]);
        let (b, _) = build_chain(&[(tok(2), 10)]);
        let (c, _) = build_chain(&[(tok(1), 11)]);
        assert_ne!(a, b, "the token must affect the anchor");
        assert_ne!(a, c, "the amount must affect the anchor");
    }

    /// Chain length is the operator's cap on total resolvable uncertainty.
    #[test]
    fn test_chain_caps_total_resolvable_uncertainty() {
        let (anchor, grants) = build_chain(&[(tok(1), 10), (tok(2), 5)]);
        let total: u64 = grants.iter().map(|g| g.amount).sum();
        assert_eq!(total, 15, "the operator fixes the ceiling in advance");

        // And there is no third grant: after both, the chain is exhausted.
        let mut current = anchor;
        for g in &grants {
            assert!(g.authorises(&current));
            current = g.next_anchor;
        }
        assert_eq!(current, CHAIN_END);
    }

    /// The model-checker fixture must actually be usable and its forged twin must
    /// actually fail, or A7's startup check would be vacuous.
    #[test]
    fn test_model_check_chain_is_not_vacuous() {
        let (anchor, valid, forged) = model_check_chain();
        assert!(valid.authorises(&anchor), "the fixture's valid grant must authorise");
        assert!(!forged.authorises(&anchor), "the fixture's forged grant must not");
    }
}
