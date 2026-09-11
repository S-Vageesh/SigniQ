use qds::attacks::{attempt_channel_tampering, attempt_forgery, attempt_impersonation, attempt_replay};
use qds::{
    estimate_forgery_probability, sign, theory_forgery_probability, verify, verify_transferability,
    Verdict, Trent,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const QUBITS: usize = 16;
const LAMBDA: usize = 4;
const MESSAGE: &[u8] = b"SIH26141 ledger entry #4711: transfer 5.000 QCO to acct 88";

#[test]
fn legitimate_signature_is_deterministically_accepted() {
    let mut rng = StdRng::seed_from_u64(1001);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let report = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert!(report.accepted, "legit signature must accept: {:?}", report.reason);
    assert_eq!(report.match_ratio, 1.0);
    assert_eq!(report.mismatches, 0);
}

#[test]
fn tampered_message_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1002);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let tampered = b"SIH26141 ledger entry #4711: transfer 9.999 QCO to acct 13";
    let report = verify(tampered, &sig, &mut trent, 0.0);
    assert!(!report.accepted, "modified message must be rejected");
    assert!(report.mismatches > 0);
}

#[test]
fn forgery_attack_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1003);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let attempt = attempt_forgery(MESSAGE, &mut trent, &mut rng);
    let report = verify(MESSAGE, &attempt.signature, &mut trent, 0.0);
    assert!(!report.accepted, "random-bit forgery must be rejected");
}

#[test]
fn impersonation_attack_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1004);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let real = b"invoice paid: 120 QCO";
    let (genuine, _) = sign(real, &mut trent, &mut rng);
    let attempt = attempt_impersonation(&genuine, real, MESSAGE);
    let report = verify(MESSAGE, &attempt.signature, &mut trent, 0.0);
    assert!(!report.accepted, "signature transplant must be rejected");
}

#[test]
fn replay_attack_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1005);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (genuine, _) = sign(MESSAGE, &mut trent, &mut rng);
    let first = verify(MESSAGE, &genuine, &mut trent, 0.0);
    assert!(first.accepted, "first presentation must accept");

    let replay = attempt_replay(&genuine, MESSAGE);
    let second = verify(MESSAGE, &replay.signature, &mut trent, 0.0);
    assert!(!second.accepted, "replay of consumed nonce must be rejected");
    assert!(second.reason.contains("replay"));
}

#[test]
fn channel_tampering_is_detected_proportionally() {
    let mut rng = StdRng::seed_from_u64(1006);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (_sig, teleports) = sign(MESSAGE, &mut trent, &mut rng);

    let attempt =
        attempt_channel_tampering(&teleports, 0.5, MESSAGE, &trent, &mut rng);
    let mut sig = attempt.signature.clone();
    sig.nonce = trent.issue_nonce(); // tamper flow uses its own fresh nonce
    let report = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert!(!report.accepted, "50% channel tampering must be rejected");
    assert!(report.mismatches > 0, "tampering must produce mismatches");
}

#[test]
fn forgery_probability_matches_theory() {
    let mut rng = StdRng::seed_from_u64(1007);
    // All-position guess forgery: (1/4)^(qubits*lambda) = (1/4)^64 ≈ 5e-39
    let theory = theory_forgery_probability(QUBITS, LAMBDA);
    assert!(theory < 1e-30, "theory bound should be astronomically small");

    // Small-parameter Monte Carlo: 1 qubit, 1 lambda => per-signature 1/4.
    let p = estimate_forgery_probability((1, 1), 4000, &mut rng);
    assert!(
        (p - 0.25).abs() < 0.05,
        "MC forgery probability {p} should approximate 1/4"
    );
}

#[test]
fn failed_verification_keeps_nonce_usable() {
    let mut rng = StdRng::seed_from_u64(1008);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    // Wrong message first (verification fails)...
    let bad = verify(b"wrong", &sig, &mut trent, 0.0);
    assert!(!bad.accepted);
    // ...the genuine message must still verify (nonce not consumed on failure).
    let good = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert!(good.accepted, "failed attempt must not burn the nonce");
}

#[test]
fn genuine_signature_yields_1acc_verdict() {
    let mut rng = StdRng::seed_from_u64(1009);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let report = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert_eq!(report.verdict, Verdict::Acc1, "clean channel => transferable");
    assert!(report.transferable());
}

#[test]
fn forged_signature_in_gray_zone_yields_0acc_not_rej_boundary() {
    // A signature with a few flipped bits lands in the gray zone (0-ACC) when
    // the mismatch fraction is in (c1, c2]. We craft one at ~6% mismatch with
    // c2 = 0.10: valid-ish locally, NOT transferable.
    let mut rng = StdRng::seed_from_u64(1010);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (mut sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    // Flip exactly 4 of 128 signature bits => 2 of 64 positions mismatch (~3%).
    for b in sig.correction_bits.iter_mut().take(4) {
        *b ^= 1;
    }
    let report = verify(MESSAGE, &sig, &mut trent, 0.10);
    assert_eq!(report.verdict, Verdict::Acc0, "few mismatches => 0-ACC gray zone");
    assert!(report.accepted, "0-ACC is still locally accepted");
    assert!(!report.transferable(), "0-ACC must not be forwarded as trusted");
}

#[test]
fn transferability_consensus_genuine_and_forged() {
    let mut rng = StdRng::seed_from_u64(1011);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);

    // Genuine: Bob accepts 1-ACC; Charlie (transferability) must also be non-REJ.
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let bob = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert_eq!(bob.verdict, Verdict::Acc1);
    let charlie = verify_transferability(MESSAGE, &sig, &mut trent, 0.10);
    assert!(charlie.accepted, "second verifier must agree on genuine signature");

    // Forged: Charlie must reject, and the attempt must not consume the nonce.
    let attempt = attempt_forgery(b"attacker payload", &mut trent, &mut rng);
    let charlie2 = verify_transferability(b"attacker payload", &attempt.signature, &mut trent, 0.10);
    assert_eq!(charlie2.verdict, Verdict::Rej);
}
