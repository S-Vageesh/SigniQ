//! Controlled attack simulations against the QDS protocol (deliverable 4).
//!
//! Each attack produces a `QuantumSignature` that is *not* a genuine
//! teleportation product, plus a label describing the threat class. The
//! verifier must reject all of them; `estimate_forgery_probability` in the
//! root module quantifies how overwhelming "must" is.

use crate::{QuantumSignature, Trent};
use rand::Rng;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackKind {
    /// Forger fabricates correction bits without any Bell measurement.
    Forgery,
    /// Attacker re-signs a different message with bits captured from a
    /// signature for another message (signature transplant).
    Impersonation,
    /// Attacker replays a previously accepted signature verbatim.
    Replay,
    /// Eve tampers with teleported qubits in flight; correction bits are
    /// genuine but the received state is disturbed.
    ChannelTampering,
}

/// A forged signature attempt plus metadata for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackAttempt {
    pub kind: AttackKind,
    pub signature: QuantumSignature,
    /// Human-readable description of what the attacker did.
    pub description: String,
    /// Original message the signature claims to cover.
    pub claimed_message: String,
}

fn message_hash(message: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(message);
    hex::encode(h.finalize())
}

/// Pure guessing forgery: random correction bits under a fresh nonce.
pub fn attempt_forgery(
    claimed_message: &[u8],
    trent: &mut Trent,
    rng: &mut impl Rng,
) -> AttackAttempt {
    let n = trent.public_key().qubit_count * trent.public_key().lambda * 2;
    AttackAttempt {
        kind: AttackKind::Forgery,
        signature: QuantumSignature {
            correction_bits: (0..n).map(|_| rng.gen_bool(0.5) as u8).collect(),
            nonce: trent.issue_nonce(),
            key_commitment: trent.public_key().correlation_commitment.clone(),
        },
        description: "Forger fabricated Bell outcomes uniformly at random (no quantum measurement performed)."
            .into(),
        claimed_message: String::from_utf8_lossy(claimed_message).into_owned(),
    }
}

/// Impersonation: take a genuine signature over `real_message` and present
/// it as a signature over `target_message` (the attacker controls neither
/// the correlations nor the nonce registry).
pub fn attempt_impersonation(
    genuine: &QuantumSignature,
    real_message: &[u8],
    target_message: &[u8],
) -> AttackAttempt {
    let _ = real_message; // captured signature is reused as-is
    AttackAttempt {
        kind: AttackKind::Impersonation,
        signature: QuantumSignature {
            correction_bits: genuine.correction_bits.clone(),
            nonce: genuine.nonce,
            key_commitment: genuine.key_commitment.clone(),
        },
        description: "Attacker transplanted a genuine signature onto a different message (no new teleportation possible without Alice's correlations).".into(),
        claimed_message: String::from_utf8_lossy(target_message).into_owned(),
    }
}

/// Replay: re-present an already-accepted signature for the same message.
pub fn attempt_replay(genuine: &QuantumSignature, message: &[u8]) -> AttackAttempt {
    AttackAttempt {
        kind: AttackKind::Replay,
        signature: QuantumSignature {
            correction_bits: genuine.correction_bits.clone(),
            nonce: genuine.nonce,
            key_commitment: genuine.key_commitment.clone(),
        },
        description: "Attacker replayed a previously accepted signature verbatim (nonce reuse)."
            .into(),
        claimed_message: String::from_utf8_lossy(message).into_owned(),
    }
}

/// Quantum channel tampering: Eve flips the state of a fraction f of the
/// teleported qubits in flight. Alice's correction bits remain genuine, but
/// Bob's corrected bits land on the wrong values with probability ≈ f·(2/3)
/// (a Pauli X/Z error flips the bit; I and ZX phase-structure does not in
/// this classical encoding).
pub fn attempt_channel_tampering(
    genuine_teleports: &[crate::TeleportResult],
    tamper_fraction: f64,
    claimed_message: &[u8],
    trent: &Trent,
    rng: &mut impl Rng,
) -> AttackAttempt {
    let lambda = trent.public_key().lambda;
    let mut bits = Vec::with_capacity(genuine_teleports.len() * 2);
    for t in genuine_teleports {
        let (b1, b2) = t.outcome.as_bits();
        if rng.gen_bool(tamper_fraction) {
            // Eve's interaction randomizes which Bell outcome Bob decodes.
            let flip = rng.gen_bool(0.5);
            bits.push(if flip { 1 - b1 } else { b1 });
            bits.push(if flip { b2 } else { 1 - b2 });
        } else {
            bits.push(b1);
            bits.push(b2);
        }
    }
    AttackAttempt {
        kind: AttackKind::ChannelTampering,
        signature: QuantumSignature {
            correction_bits: bits,
            nonce: {
                let _ = lambda;
                0 // nonce supplied by caller flow in server; 0 = take a fresh one
            },
            key_commitment: trent.public_key().correlation_commitment.clone(),
        },
        description: format!(
            "Eve disturbed {:.0}% of teleported qubits in flight; correction bits are genuine but decode inconsistently.",
            tamper_fraction * 100.0
        ),
        claimed_message: String::from_utf8_lossy(claimed_message).into_owned(),
    }
}
