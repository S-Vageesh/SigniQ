# SIH26141 — Quantum-Secured Pipeline: Complete Project Guide

**Audience:** team members who need to understand, present, and extend this project — no
prior quantum computing or Rust knowledge assumed.

**What this project is:** an end-to-end simulation of quantum key distribution (QKD) using
the six-state protocol, with statistical eavesdropping detection (Hoeffding bound), message
authentication (HMAC-SHA256), a Rust REST/SSE backend, and an interactive web dashboard.

**What it demonstrates:** a clean channel produces a shared secret key and authenticated
messages; an eavesdropper unavoidably disturbs the quantum channel, raising the error rate
above a statistically safe threshold, which causes key generation to be aborted.

---

## Table of contents

- [Part 1 — Theory: quantum cryptography from zero](#part-1--theory-quantum-cryptography-from-zero)
  - [1.1 The problem QKD solves](#11-the-problem-qkd-solves)
  - [1.2 Qubits, bases, eigenstates](#12-qubits-bases-eigenstates)
  - [1.3 Measurement, collapse, and the no-cloning theorem](#13-measurement-collapse-and-the-no-cloning-theorem)
  - [1.4 From BB84 to six-state](#14-from-bb84-to-six-state)
  - [1.5 The six-state protocol, step by step](#15-the-six-state-protocol-step-by-step)
  - [1.6 Why eavesdropping is detectable (the 1/3 derivation)](#16-why-eavesdropping-is-detectable-the-13-derivation)
  - [1.7 Sifting and QBER](#17-sifting-and-qber)
  - [1.8 Error correction (not implemented)](#18-error-correction-not-implemented)
  - [1.9 Privacy amplification](#19-privacy-amplification)
  - [1.10 Finite-key security: the Hoeffding bound](#110-finite-key-security-the-hoeffding-bound)
  - [1.11 Authenticating messages with the key](#111-authenticating-messages-with-the-key)
- [Part 2 — Codebase walkthrough](#part-2--codebase-walkthrough)
  - [2.1 Repository layout](#21-repository-layout)
  - [2.2 quantum crate](#22-quantum-crate)
  - [2.3 detection crate](#23-detection-crate)
  - [2.4 attacks crate](#24-attacks-crate)
  - [2.5 crypto crate](#25-crypto-crate)
  - [2.6 main_app crate (CLI demo)](#26-main_app-crate-cli-demo)
  - [2.7 server crate (API + SSE)](#27-server-crate-api--sse)
  - [2.8 frontend (React dashboard)](#28-frontend-react-dashboard)
  - [2.9 End-to-end data flow](#29-end-to-end-data-flow)
- [Part 3 — Running the project](#part-3--running-the-project)
- [Part 4 — Testing](#part-4--testing)
- [Part 5 — Demo script for presentations](#part-5--demo-script-for-presentations)
- [Part 6 — Limitations and roadmap](#part-6--limitations-and-roadmap)
- [Glossary](#glossary)

---

# Part 1 — Theory: quantum cryptography from zero

## 1.1 The problem QKD solves

Nearly all encryption used today (TLS, AES, RSA key exchange) rests on *computational
hardness*: assumptions that certain math problems are too expensive to solve. Two weaknesses:

1. **Shor's algorithm on a large quantum computer breaks RSA/ECC outright.** Traffic
   recorded today can be stored and decrypted later ("harvest now, decrypt later").
2. Computational hardness is a *belief*, not a physical law.

**Quantum key distribution (QKD)** takes a different route: the security of the key
exchange comes from the **laws of physics**, not computational difficulty. The core insight:

> Measuring an unknown quantum state unavoidably disturbs it. An eavesdropper cannot copy
> or observe the key traffic without leaving statistical fingerprints.

QKD does **not** encrypt your data. It *distributes a shared secret key* between two
parties (Alice = sender, Bob = receiver). That key is then used with conventional symmetric
crypto (here: HMAC-SHA256; in practice also AES) to protect messages. This pairing is
called **quantum-safe hybrid cryptography**.

Two more properties worth stating precisely:

- **Eavesdropping detection, not prevention.** Eve can still listen; the point is that she
  *cannot listen undetected*. If the channel looks compromised, Alice and Bob simply throw
  the key away and start over.
- **Authentication of the classical channel is required.** QKD must run over an
  authenticated (not necessarily secret) classical channel, otherwise a
  man-in-the-middle can impersonate both sides. Small pre-shared credentials or
  post-quantum signatures bootstrap this.

## 1.2 Qubits, bases, eigenstates

A **qubit** is a quantum two-level system. While a classical bit is 0 *or* 1, a qubit can
exist in a **superposition** — a combination of both — until it is measured.

To *measure* a qubit you must choose a **basis** — a physical "question" you ask of it.
This project uses the three **Pauli bases**, named after the Pauli matrices:

| Basis | Pauli matrix | Possible outcomes (eigenstates) |
|---|---|---|
| X | σx = [[0,1],[1,0]] | +1 or −1 |
| Y | σy = [[0,−i],[i,0]] | +1 or −1 |
| Z | σz = [[1,0],[0,−1]] | +1 or −1 |

An **eigenstate** of a basis is a state that gives a *deterministic* answer when measured
in that basis: measuring the +1 eigenstate of Z in the Z basis always yields +1. Every
qubit state is simultaneously an eigenstate of exactly *one* Pauli basis (here), and when
measured in that basis it behaves classically.

The crucial fact — the one the whole protocol rides on:

> If you measure a qubit prepared in the eigenstate of basis A, **using a different basis
> B**, the outcome is **uniformly random** (+1 or −1 with probability ½ each), and the
> qubit's state **collapses** to an eigenstate of B. The original state is destroyed.

In code (see `quantum/src/lib.rs`), a prepared qubit is the pair
`(PauliBasis, PauliState)` — "what question it answers" and "what the answer is".
`PauliState::Positive → bit 1`, `Negative → bit 0` (see `PauliState::as_bit`).

## 1.3 Measurement, collapse, and the no-cloning theorem

Two physical facts make QKD possible:

1. **Measurement disturbance.** As above: measuring in the wrong basis randomizes and
   destroys the state. There is no way to "peek" gently at an unknown quantum state.
2. **The no-cloning theorem.** There exists no physical process that copies an unknown
   quantum state perfectly. Eve cannot take a qubit, keep a photocopy, and forward the
   original untouched.

Together: any eavesdropper who interacts with the qubits must *measure* them, measuring
disturbs them, and the disturbance shows up as errors that honest users can measure.

## 1.4 From BB84 to six-state

**BB84** (Bennett & Brassard, 1984) is the famous two-basis QKD protocol (rectilinear +
diagonal polarizations). It works, but its security proofs must handle the asymmetry that
Eve guesses the right basis ½ the time.

The **six-state protocol** (Bruss, 1998) uses **three mutually unbiased bases** (X, Y, Z).
"B mutually unbiased with A" means: measuring an A-eigenstate in B yields a perfectly
random outcome. Three bases give a *more symmetric* protocol:

- Eve guesses a given qubit's basis correctly only **1/3** of the time (vs 1/2 in BB84),
  so a full intercept-resend attack causes **more disturbance (QBER ≈ 33%) vs 25% in BB84** —
  easier to detect.
- The channel error statistics are direction-independent, which simplifies analysis and
  enables stronger checks.

Trade-off: with three bases, fewer transmission rounds survive sifting (see §1.7) —
1/3 instead of 1/2. Higher detectability, lower yield. This project implements six-state.

## 1.5 The six-state protocol, step by step

1. **Preparation (Alice).** For each of N qubits, Alice randomly picks a basis
   (X, Y, or Z, uniform) and a sign (+1 or −1, uniform), and prepares that eigenstate.
   Her secret record is the list of `(basis, sign)` — the raw material of the key.
   *Code:* `QuantumKeyGenerator::generate_eigenstates`.
2. **Transmission.** Qubits travel to Bob over the (insecure, possibly eavesdropped)
   quantum channel. *Simulated in `ChannelSession::transmit`.*
3. **Measurement (Bob).** Bob independently picks a random basis for each arriving qubit
   and measures, getting +1/−1. *Code:* `random_basis(rng)`, then the outcome rules in
   §1.7.
4. **Sifting** over the authenticated classical channel: they reveal their **bases**
   (not the sign bits!) and keep only positions where bases matched (§1.7).
5. **Parameter estimation:** they sacrifice a random sample of the sifted bits, compare
   them publicly, and estimate **QBER** — the quantum bit error rate (§1.7). If QBER is
   too high → eavesdropper (or too much noise) → **abort**. This project's
   `ThreatDetector` implements the decision rule.
6. **Error correction:** reconcile remaining differences (not simulated — §1.8).
7. **Privacy amplification:** compress the reconciled key to a shorter, provably uniform
   secret (§1.9).
8. **Use:** the final key authenticates/encrypts traffic (§1.11).

## 1.6 Why eavesdropping is detectable (the 1/3 derivation)

This is the heart of the project. Consider **one** qubit under an intercept-resend attack,
where Eve measures every qubit in a random basis and resends what she got.

Alice chose basis A, sign s. Eve measures in basis E:

- **E = A** (probability 1/3): Eve reads the true sign, resends the original state —
  no disturbance. Bob learns nothing has happened… on this qubit.
- **E ≠ A** (probability 2/3): Eve's outcome is random; she resends an **E-eigenstate**
  with a random sign. The original state is destroyed.

Now Bob measures in basis B, and we track what Alice and Bob see **after sifting**
(B = A, which happens with probability 1/3 — Bob's basis is also uniform over 3):

| Eve's basis | Probability (given B = A) | Bob's bit vs Alice's | Error? |
|---|---|---|---|
| E = A | 1/3 | deterministic, correct | never |
| E ≠ A | 2/3 | Bob measures an E-eigenstate in basis A ⇒ **uniform random** | ½ |

So the probability a sifted bit is **wrong**:

```
QBER = P(E≠A) × P(random outcome wrong) = (2/3) × (1/2) = 1/3 ≈ 33.3%
```

**Partial attack** — Eve intercepts only a fraction f of qubits (this project's
`intercept_ratio`): by linearity of expectation,

```
QBER(f) = f × 1/3 = f / 3
```

Intercept 30% of qubits → expect ~10% QBER. This exact relationship is what the
dashboard's sweep chart shows, and what the unit test
`partial_ratio_yields_intermediate_qber` asserts.

One subtlety the simulation gets right (see the comments in `ChannelSession::transmit`):
after Eve resends in *her* basis, Bob's outcome is deterministic only if Bob happens to
measure in **Eve's** basis; otherwise it's random. Sifting is always done against
**Alice's** basis. The code carries `(current_state, current_basis)` — the state actually
on the wire — to model this faithfully.

## 1.7 Sifting and QBER

**Sifting.** Bob's basis matches Alice's with probability 1/3 (uniform over 3 bases).
Only those positions can carry correlated bits, so ~N/3 of transmissions survive:
e.g. 20,000 qubits → ~6,700 sifted bits. Alice and Bob reveal *bases only* publicly;
basis revelation leaks nothing about the key bits.

**QBER (quantum bit error rate)** — measured on the sifted key:

```
QBER = (# mismatching sifted bits) / (# sifted bits)
```

*Code:* `ChannelSession::qber()` and, in batch mode, `SiftedKeyResult.mismatch_rate`.
In an ideal noiseless channel, QBER = 0 means no interception. Real hardware adds noise,
which is exactly why the detection rule needs a statistical margin (§1.10) rather than
"QBER > 0 ⇒ attack".

## 1.8 Error correction (not implemented)

Real sifted keys still contain a few percent of errors from channel noise. Protocols like
**Cascade** or **LDPC reconciliation** let Alice and Bob agree on identical strings,
leaking a calculable number of bits to a potential eavesdropper in the process (this
leakage is what makes the next stage necessary). This project **skips** error correction —
in the simulated clean channel Alice's and Bob's sifted bits are equal by construction, and
the code comments and dashboard both call out where reconciliation would run
("a real pipeline runs error correction here before PA" in `main_app/src/main.rs`).

## 1.9 Privacy amplification

Even after sifting and reconciliation, Eve may hold *partial* information (her
measurements, the bits leaked by error correction). **Privacy amplification** compresses
the long, partially-secure string into a shorter, almost perfectly uniform secret using a
*universal2 hash family*: with output length reduced by (roughly) the number of leaked
bits, Eve's expected information about the output is negligible (leftover hash lemma).

**This project uses a simplified version:** SHA-256 over all sifted bits, producing a
256-bit (64-hex-char) secret — `quantum::privacy_amplification`. Since the simulation
either flags the channel as compromised (and aborts) or produces a perfectly correlated
key, the entropy accounting of a full two-universal-hash implementation is not required
for the demo to be sound. The code and README both mark this as a known simplification.

## 1.10 Finite-key security: the Hoeffding bound

Suppose the measured QBER is q̂ over n sifted bits. Is the channel truly clean, or did we
just get lucky with a small sample? The **two-sided Hoeffding inequality** bounds how far
an empirical rate can deviate from the true rate p:

```
P(|q̂ − p| ≥ ε) ≤ 2·exp(−2nε²)
```

Setting the right side ≤ δ (our tolerated failure probability) and solving for ε:

```
ε(n) = √( ln(2/δ) / (2n) )
```

**Decision rule (implemented in `detection::ThreatDetector`):**

```
dynamic_threshold = base_threshold + ε(n)
channel authentic  ⇔  QBER ≤ dynamic_threshold
```

Why add ε instead of comparing against the base threshold directly? It is a
*finite-sample safety margin*: with few sifted bits, q̂ is noisy, so the bar is lenient;
as n grows, ε shrinks like √(1/n) and the bar tightens toward the base threshold. Hoeffding
makes **no variance assumptions** (unlike a normal-approximation / Chernoff-style bound),
which suits an adversarial channel.

Concrete numbers at δ = 0.05 (the default `confidence_delta`):

| n (sifted bits) | ε | threshold (base 15%) |
|---|---|---|
| 100 | 17.2% | 32.2% |
| 1,000 | 5.4% | 20.4% |
| 6,700 (20k qubits) | 2.1% | 17.1% |
| 33,000 (100k qubits) | 0.95% | 15.9% |

You can watch this "threshold tightening" live in the dashboard: the dashed lines converge
as the run progresses. Note the flip side: *fewer* samples ⇒ *more* forgiving threshold ⇒
a weak partial attack can slip through. Security scales with key length — a real design
trade-off you can demonstrate by sweeping key length at a fixed intercept ratio.

## 1.11 Authenticating messages with the key

The distilled secret is used to **HMAC-SHA256**-authenticate a message
(`crypto` crate): tag = HMAC(key, message), sent alongside the message; the receiver
recomputes and compares in constant time (`verify_message_hmac`). HMAC's security needs a
secret, uniform key — exactly what QKD + privacy amplification deliver. Any tampering with
the message invalidates the tag. In the demo, the compromised channel produces **no key at
all**, so nothing can be authenticated — the abort is the security feature.

---

# Part 2 — Codebase walkthrough

## 2.1 Repository layout

```
sih26141/
├── Cargo.toml            # Rust workspace manifest (all crates, resolver 2)
├── quantum/              # Six-state QKD physics core (lib)
├── detection/            # Hoeffding-bound threat detector (lib)
├── attacks/              # Attack scenario wrappers (lib)
├── crypto/               # HMAC-SHA256 message authentication (lib)
├── main_app/             # Original CLI demo binary
├── server/               # Axum HTTP API + SSE + static file serving
├── frontend/             # React + TypeScript + Recharts dashboard (Vite)
│   └── src/
│       ├── App.tsx             # State orchestration + layout
│       ├── api.ts              # Typed REST client
│       ├── useRunStream.ts     # SSE subscription hook
│       └── components/
│           ├── StatusCard.tsx  # Per-scenario verdict cards
│           ├── LiveMonitor.tsx # Real-time QBER chart + stats + event log
│           └── SweepPanel.tsx  # QBER-vs-intercept-ratio bar chart
├── tests/                # Workspace integration tests
├── scripts/run_simulations.sh  # build → test → CLI demo → serve dashboard
└── docs/PROJECT_GUIDE.md       # This document
```

Dependency direction: `server → {quantum, detection, attacks, crypto}`, `attacks →
quantum`, everything else standalone. The physics crates never know HTTP exists; the
server never does physics itself.

## 2.2 quantum crate

**Files:** `quantum/src/lib.rs` (+ unit tests at the bottom), `quantum/Cargo.toml`
(deps: `rand`, `sha2`, `hex`).

**Types**

- `PauliBasis { X, Y, Z }` — the three measurement bases (§1.2).
- `PauliState { Positive, Negative }` — the ±1 eigenvalues; `as_bit()` maps
  Positive→1, Negative→0. This mapping *is* the encoding of key bits.
- `(PauliBasis, PauliState)` — one prepared qubit: Alice's secret preparation.

**`QuantumKeyGenerator`**
- `new(key_length)` — validates length > 0 (returns `Result`).
- `generate_eigenstates(&mut rng)` — Alice's preparation: uniform basis ∈ {X,Y,Z},
  uniform sign ∈ {+,−}, `key_length` times. Deterministic given a seeded RNG — the demo
  and tests exploit this for reproducibility.

**`ChannelSession`** — the physics engine, one qubit at a time (added for live streaming):

- `new(intercept_ratio)` — 0.0 = clean channel, 1.0 = Eve measures every qubit, f = partial
  attack (§1.6). Clamped to [0,1].
- `transmit(basis_alice, state_alice, rng) -> Option<TransmissionStep>` — the protocol in
  miniature, in order:
  1. Bob picks a uniform random basis (`random_basis`).
  2. Eve intercepts this qubit with probability `intercept_ratio`; if her basis differs
     from the one on the wire, the state **collapses** to a random sign in *her* basis.
  3. If Bob's basis ≠ Alice's → qubit discarded (returns `None`; never sifted).
  4. Otherwise: Bob's bit is deterministic if he measures in the wire's basis, otherwise
     uniform random; mismatches counted; both Alice's and Bob's bits retained
     ("keep every sifted bit — errors are only revealed later").
- `qber()`, `sifted_count()`, `mismatch_count()`, `matching_bases_count()` — running stats
  for the live monitor; `qber()` guards division by zero (returns 1.0).
- `finish() -> SiftedKeyResult` — final batch result.

**Batch API**

- `simulate_six_state_transmission(key, intercept_resend, rng)` — legacy two-mode wrapper
  (bool ⇒ ratio 0.0/1.0). Kept so `attacks` and `main_app` compile unchanged.
- `simulate_six_state_transmission_ratio(key, ratio, rng)` — loop of `ChannelSession`.

**`SiftedKeyResult`** — Bob's sifted bits, Alice's sifted bits (both retained: the diff
*is* the QBER evidence), mismatch rate, matching-bases count.

**`privacy_amplification(bits) -> hex String`** — SHA-256 of the sifted bits (§1.9).

**Unit tests** (bottom of the file) assert the physics: ratio 0.0 ⇒ identical keys and
QBER 0.0; ratio 1.0 ⇒ differing keys and QBER ∈ (0.2, 0.45); ratio 0.3 ⇒ QBER ∈
(0.04, 0.16) ≈ 0.1 (§1.6's f/3).

## 2.3 detection crate

**Files:** `detection/src/lib.rs`. No external deps — pure math.

**`ThreatDetector`**
- `new(base_threshold)` — base QBER budget (0..1 validated), default δ = 0.05.
- `with_confidence_delta(delta)` — builder to override δ (strictly between 0 and 1).
- `evaluate_signature(mismatch_rate, matching_bases_count) -> DetectionResult` — §1.10
  verbatim: `slack = √(ln(2/δ)/(2n))`, `dynamic_threshold = base + slack` (capped at 1.0),
  authentic ⇔ qber ≤ threshold. Special case n = 0 → "complete signal loss", flagged.

**`DetectionResult`** — `is_authentic`, `mismatch_rate`, `dynamic_threshold`,
`threat_flagged` (logical complement), and a human-readable `note`.

## 2.4 attacks crate

**Files:** `attacks/src/lib.rs`. A thin façade giving scenarios names:

- `AttackSimulator::run_secure_simulation(key, rng)` — clean channel.
- `AttackSimulator::run_intercept_resend_simulation(key, rng)` — full intercept-resend.

Both delegate to the quantum batch simulator. (The server uses the ratio API directly for
partial attacks; the CLI demo uses these two.)

## 2.5 crypto crate

**Files:** `crypto/src/lib.rs` (deps: `hmac`, `sha2`, `hex`).

- `compute_message_hmac(secret_hex, message) -> hex tag` — HMAC-SHA256 with the QKD-derived
  key. Hex-decodes the secret; returns `Result` with descriptive errors.
- `verify_message_hmac(secret_hex, message, expected_tag_hex) -> bool` — recomputes and
  compares via `mac.verify_slice` (**constant-time** comparison, not `==`, which is the
  timing-attack-safe pattern).

## 2.6 main_app crate (CLI demo)

**Files:** `main_app/src/main.rs`. The original prototype entry point; still useful as a
fast, dependency-light sanity check. Flow: seed an RNG → generate eigenstates → run the
secure scenario → evaluate with the detector → (if authentic) privacy amplification →
HMAC a sample message → then the same for a full intercept-resend attack. Ends with a
"SECURITY ALERT" line when the attack is flagged. Uses seeded RNG (42) for reproducibility;
a production system would use `OsRng`.

## 2.7 server crate (API + SSE)

**Files:** `server/src/main.rs`, `server/Cargo.toml` (deps: workspace crates + `axum`,
`tokio`, `tokio-stream`, `serde(-json)`, `tower-http` (cors, fs), `rand`).

**Endpoints**

| Route | Method | Behavior |
|---|---|---|
| `/api/health` | GET | `"ok"` liveness probe (drives the online/offline pill) |
| `/api/run` | POST | Full run. Body: `{key_length?, base_threshold?, intercept_ratio?, message?, seed?, pace_ms?}`. Default: two scenarios — secure (0.0) and attack (1.0). Returns `RunResponse` |
| `/api/simulate` | POST | Sweep. Body: `{intercept_ratios: [f64; ≤32], key_length?, base_threshold?, seed?}` → per-ratio `ScenarioResult`s |
| `/api/events` | GET | **SSE** stream of `RunEvent`s; replays the last run's results to late subscribers; keep-alive every 15 s |
| `/` (fallback) | GET | Serves `frontend/dist` when built (single-port deployment), else API-only mode |

**Run pipeline (what `POST /api/run` actually does)**

1. Validate inputs (key_length ∈ [500, 200_000], thresholds ∈ [0,1], ratios ∈ [0,1],
   message ≤ 10 KB). Errors are structured JSON with HTTP 400.
2. `run_id` = atomic counter; `seed` from body or wall-clock nanos.
3. Heavy work is moved **off the async reactor** into `tokio::task::spawn_blocking` —
   simulation is CPU-bound and would otherwise stall the HTTP server.
4. For each scenario, `execute_scenario_streaming`:
   - generate Alice's qubits (seeded per scenario for reproducibility),
   - feed `ChannelSession` one qubit at a time; after every ~1% batch, publish a
     `Progress` SSE event with processed/total, sifted, mismatches, running QBER, **and the
     Hoeffding threshold at that sample size** (same formula as the detector — the live
     chart's dashed line), sleeping `pace_ms` per batch so humans can watch,
   - finalize: `ThreatDetector` verdict; if authentic → privacy amplification → HMAC the
     caller's message; compute `first_divergence` (first index where Alice's and Bob's
     sifted bits differ — a visceral "Eve was here" marker for the UI).
5. Publish `Result` and `Done` events; store the response for SSE replay; return JSON.

**`ScenarioResult` (JSON)** — everything the dashboard needs: scenario, ratio, raw and
sifted lengths, `qber`, `dynamic_threshold`, `is_authentic`, `threat_flagged`,
`first_divergence`, and (when authentic) `derived_secret`, `hmac_tag`, `hmac_valid`.

**`RunEvent` (SSE, tagged JSON)** — `progress {…}` | `result {…}` | `done {run_id}`.
The frontend filters by `run_id` and toggles its "streaming" state on `done`.

**Configuration:** `PORT` env var (default 8080), `FRONTEND_DIST` override for the static
dir. Bound to 127.0.0.1. CORS is permissive for the dev setup (Vite on 5173 proxying to
8080).

## 2.8 frontend (React dashboard)

**Stack:** Vite + React 19 + TypeScript + Recharts. No CSS framework — a hand-rolled dark
"SOC console" theme in `index.css`. Dev mode proxies `/api` → `127.0.0.1:8080`
(`vite.config.ts`); production build is a static bundle the Rust server serves itself.

**`api.ts`** — typed mirrors of the server DTOs (`ScenarioResult`, `RunResponse`,
`RunEvent` union) and three calls: `startRun`, `runSweep`, `healthCheck`.

**`useRunStream.ts`** — one `EventSource` to `/api/events`, auto-reconnect (2 s backoff)
on error; the handler is kept in a ref so the connection survives re-renders.

**`App.tsx`** — owns all state:
- *Parameters:* key length (1k–100k), base threshold, streaming pace (ms/batch), optional
  custom intercept-ratio mode, optional fixed seed, message to authenticate.
- *Run lifecycle:* clears state, sets the "accepting events" ref, POSTs `/api/run`,
  latches `run_id`, ingests SSE events (progress → `live` map of per-scenario series;
  result → verdict log lines; done → unlock the button).
- *Sweep:* POSTs 11 ratios (0.0–1.0 step 0.1) to `/api/simulate`, maps results to
  `{ratio, qber, threshold, theory: ratio/3}`.
- *Health:* polls `/api/health` every 10 s for the header pill.
- Renders: header, parameters panel, status cards, live monitor, sweep panel, key-material
  panel, footer.

**`components/StatusCard.tsx`** — one card per scenario; colored top border by state
(green/red/animated blue while streaming), live progress bar, three metrics (QBER /
dynamic threshold / sifted bits), final chip (✓ AUTHENTIC / ✗ THREAT FLAGGED) and an
alert strip when aborted.

**`components/LiveMonitor.tsx`** — the centerpiece: per-scenario stat blocks
(transmitted %, sifted, mismatches, live QBER) and a Recharts `LineChart` with one solid
line per scenario (live QBER) plus dashed threshold lines converging as n grows (§1.10),
a "base 15%" reference line, capped 600-point window, and the scrolling event log.

**`components/SweepPanel.tsx`** — grouped bar chart: measured QBER vs theoretical ratio/3
per intercept ratio, with the Hoeffding detection threshold as a red reference line —
the "detection fires past ~60–70% interception" picture.

## 2.9 End-to-end data flow

```
 Browser (React)                 Rust server                    Physics crates
──────────────────────────────────────────────────────────────────────────────────
 POST /api/run ───────────────▶ validate, spawn_blocking ───▶ QuantumKeyGenerator
                                     │                          generate_eigenstates
                                     │ for each qubit ────────▶ ChannelSession::transmit
                                     │ every ~1% batch ───────▶ running QBER + ε(n)
 GET /api/events ◀── SSE progress ───┘ (broadcast channel)
   • bars move, chart grows, dashed threshold converges
                               finalize ──────────────────────▶ ThreatDetector::evaluate_signature
                               if authentic ──────────────────▶ privacy_amplification
                                                                 crypto::compute_message_hmac
 ◀── SSE result + done ── JSON RunResponse
   • verdict chips, key material panel, event log
 POST /api/simulate ──────────▶ sweep ratios ──────────────────▶ batch simulator per ratio
   • SweepPanel bars: measured vs theory vs threshold
```

---

# Part 3 — Running the project

**Toolchain:** Rust ≥ 1.70 (on Windows without Visual Studio, install the
`stable-x86_64-pc-windows-gnu` toolchain — `rustup default stable-x86_64-pc-windows-gnu` —
it bundles its own linker), Node.js ≥ 18 (only for the frontend).

```bash
cd sih26141

# 1. Build + run everything headless (build, tests, CLI demo):
./scripts/run_simulations.sh

# 2. Web dashboard — one-time frontend build, then serve:
cd frontend && npm install && npm run build && cd ..
PORT=8080 cargo run -p server
# → open http://127.0.0.1:8080

# 3. Frontend development with hot reload (second terminal):
cd frontend && npm run dev        # http://localhost:5173, /api proxied to :8080
```

**Configuration:** `PORT` (default 8080), `FRONTEND_DIST` (static dir override).

**Troubleshooting**
- *Address already in use* — a previous `server.exe` still holds the port:
  `taskkill //F //IM server.exe` (Git Bash) then restart.
- *`cargo: command not found` in Git Bash* — `export PATH="$USERPROFILE/.cargo/bin:$PATH"`.
- *No frontend at `/`* — build `frontend/dist` first, or set `FRONTEND_DIST`.
- *Reproducible runs* — enter the same Seed in the UI (or `seed` in the API body).

---

# Part 4 — Testing

`cargo test --workspace` runs everything (currently 6 tests, all passing):

**`tests/integration_tests.rs`** (cross-crate, the "system tests")
1. `test_secure_pipeline_end_to_end` — clean channel ⇒ Alice's and Bob's sifted keys are
   *exactly equal*; detector says authentic; PA + HMAC verify, and a tampered message
   fails verification.
2. `test_attack_detection_pipeline` — full intercept-resend ⇒ keys differ, detector flags
   the threat, no key is produced.
3. `test_input_validation_guards` — zero key length, out-of-range thresholds, and an
   invalid δ are all rejected.

**`quantum/src/lib.rs` (unit)** — the physics invariants:
4. `zero_ratio_matches_secure_channel` — ratio 0.0 ⇒ QBER 0.0, keys identical.
5. `full_ratio_matches_intercept_resend` — ratio 1.0 ⇒ QBER ∈ (0.2, 0.45) ≈ 1/3 (§1.6).
6. `partial_ratio_yields_intermediate_qber` — ratio 0.3 ⇒ QBER ≈ 0.1 — the f/3 law.

**Manual/visual checks** — dashboard run end-to-end (verdicts, live chart convergence,
sweep crossing the threshold near ratio ≈ 0.6–0.7 at base 15%), SSE `done` event unlocking
the button, health pill turning red if the API stops.

---

# Part 5 — Demo script for presentations

1. **Open the dashboard** (server + built frontend running). Point out "API online".
2. **Click "Run Secure + Attack"** (defaults are fine; 20k qubits streams ~10 s).
   Narrate: *"Alice sends 20,000 qubits; Bob's random bases sift about a third of them.
   Watch the left card — the channel is clean, QBER sits at 0%, and we distill a secret
   key and HMAC-sign a message. Watch the right — Eve measured every qubit; the error
   rate converges to the theoretical one-third; the detector aborts key generation."*
3. **Pause mid-stream** on the Live Monitor: the dashed threshold lines are tightening as
   samples accumulate — that is the finite-key Hoeffding margin (§1.10) computed live.
4. **Run the parameter sweep.** Measured bars track the theory line ratio/3; the red
   threshold line crosses them around 60–70% interception at base 15%.
   *"Eve can hide below the line by intercepting only a fraction of qubits — that's the
   fundamental detection-vs-yield trade-off, and the key-length slider is the counter."*
5. **Enable "Custom attack ratio",** set ~50%, run: border-**line** channel. Then show
   that raising key length (more samples ⇒ smaller ε) tips the same attack into flagged.
6. **Show the CLI** (`cargo run -p main_app`) as the same pipeline in 2 seconds flat.

**Likely Q&A**
- *Why 1/3 and not 1/4?* Six-state: Eve's basis is wrong 2/3 of the time, and then the
  sifted bit is wrong 1/2 ⇒ 2/3 × 1/2 = 1/3 (§1.6). BB84 would give 1/4.
- *Why do some attacks pass?* Finite statistics: ε(n) shrinks with n; below-threshold
  interception is the known trade-off — mitigate with longer keys (§1.10).
- *Is the key truly random?* Simulation uses a seeded PRNG for reproducibility; hardware
  QKD uses quantum physical random number generators (roadmap, §6).
- *Where does this run in real life?* Fiber/free-space photon transmission between
  dedicated QKD devices; this project is the control plane + analytics around that physics.

---

# Part 6 — Limitations and roadmap

**Known simplifications (also flagged in code/README)**
1. No error-correction/reconciliation stage (§1.8); secure-case keys agree by construction.
2. Privacy amplification is a fixed SHA-256, not a universal2 hash sized by
   entropy-vs-leakage accounting (§1.9).
3. Randomness is a seeded PRNG (reproducibility), not a CSPRNG/QRNG.
4. No channel noise model — real QBER is noise + attack, complicating detection.
5. Plain-HTTP local API with permissive CORS; no auth on the control plane.
6. `detection` treats each run independently (no multi-run correlation/audit trail).

**Natural next steps, roughly in order of value-to-effort**
1. **Cascade-style error correction** with QBER-dependent leak accounting → feed real
   numbers into a proper leftover-hash privacy-amplification length.
2. **Universal2 hashing** (e.g. Toeplitz matrices) with explicit entropy budget.
3. **OsRng** behind a feature flag (`--features insecure-seeded` for demos).
4. **Channel-noise slider** (depolarizing channel) → detection under realistic noise;
   ties directly into the threshold story.
5. **Run history + export** (CSV/JSON) for judges to inspect numbers after the demo.
6. **HTTPS + token auth** on the API; lock down CORS in production.
7. **More attack models** (PNS attack, imperfect sources, detector blinding) — each is a
   small extension of `ChannelSession` and makes the threat panel richer.
8. **Entanglement-based variant (BBM92/CHSH)** — bigger lift, strong "wow" factor:
   violating Bell inequality as an eavesdropper test.

---

# Glossary

| Term | Meaning |
|---|---|
| **Alice / Bob / Eve** | Sender / receiver / eavesdropper (standard names) |
| **Basis** | The measurement "question" (here X, Y, Z Pauli bases) |
| **Eigenstate** | State answering a basis's question deterministically (+1 or −1) |
| **Collapse** | Wrong-basis measurement destroys the state, outcome random |
| **No-cloning theorem** | Unknown quantum states cannot be copied |
| **Sifting** | Keep only rounds where Alice's and Bob's bases matched |
| **QBER** | Quantum bit error rate: fraction of wrong bits in the sifted key |
| **Intercept-resend** | Eve measures each qubit and forwards the result; induces QBER ≈ f/3 |
| **Hoeffding bound** | P(|q̂−p| ≥ ε) ≤ 2e^(−2nε²); gives the finite-sample margin ε(n) |
| **Privacy amplification** | Compression of a partially-secure key to a uniform secret |
| **HMAC** | Keyed hash authenticating a message (SHA-256 here) |
| **SSE** | Server-sent events: one-way HTTP stream used for live progress |
| **Six-state protocol** | QKD over three mutually unbiased bases (X, Y, Z) |
| **QKD** | Quantum key distribution — physics-secured key exchange |

---

*Generated for the SIH26141 team. Numbers in examples (thresholds, QBERs) come from the
project's own simulations; theory references: Bennett & Brassard 1984 (BB84); Bruss 1998
(six-state); Hoeffding 1963 (the bound).*
