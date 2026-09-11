# SIH26141 — Quantum-Secured Pipeline

Six-state QKD simulation with Hoeffding-bound eavesdropping detection, HMAC
message authentication, and a full web dashboard.

## Architecture

```
sih26141/
├── quantum/    Six-state prepare-and-measure QKD core
│                 • QuantumKeyGenerator  — Alice's Pauli eigenstate prep
│                 • ChannelSession       — incremental transmission (streaming)
│                 • simulate_six_state_transmission(_ratio) — batch simulation
│                 • privacy_amplification — SHA-256 key compression
├── detection/  ThreatDetector with two-sided Hoeffding bound:
│                 ε = √(ln(2/δ) / 2n), dynamic threshold = base + ε
├── attacks/    Intercept-resend eavesdropping scenario wrappers
├── crypto/     HMAC-SHA256 message authentication over the derived key
├── main_app/   Original CLI demo binary
├── server/     Axum REST + SSE API, serves the built dashboard
├── frontend/   React + TypeScript + Recharts dashboard (Vite)
├── tests/      Integration tests (secure pipeline, attack detection, validation)
└── scripts/    run_simulations.sh — build, test, demo, serve
```

## Running the dashboard

Requires Rust (windows-gnu toolchain works, no MSVC needed) and Node.js ≥ 18.

```bash
# one-time: build the dashboard
cd frontend && npm install && npm run build && cd ..

# start API + dashboard on http://127.0.0.1:8080
PORT=8080 cargo run -p server
```

Or everything at once (build + tests + CLI demo + dashboard):

```bash
./scripts/run_simulations.sh
```

Frontend development mode with hot reload (proxies /api to :8080):

```bash
cd frontend && npm run dev     # http://localhost:5173
```

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Liveness probe |
| `/api/run` | POST | Simulation run: `key_length`, `base_threshold`, `intercept_ratio` (optional), `message`, `seed`, `pace_ms` |
| `/api/simulate` | POST | Sweep over `intercept_ratios` (up to 32 values) |
| `/api/events` | GET | SSE stream: `progress` / `result` / `done` events |

```bash
curl -X POST localhost:8080/api/run \
  -H 'Content-Type: application/json' \
  -d '{"key_length": 3000, "seed": 42, "pace_ms": 0}'
```

## What the simulation shows

- **Secure channel** — sifted keys match exactly; QBER 0.00%; a 256-bit key is
  distilled via SHA-256 privacy amplification and used to HMAC-authenticate a
  message.
- **Intercept-resend attack** — Eve measures and resends qubits; wrong-basis
  measurements disturb the state, driving QBER to ≈ 1/3. The Hoeffding bound
  flags the channel and key distillation is aborted.
- **Partial eavesdropping** — QBER ≈ intercept_ratio / 3 (see the sweep chart);
  detection fires once measured QBER crosses base + ε(n).

## Tests

```bash
cargo test --workspace
```

Covers the end-to-end secure pipeline, attack detection, input validation, and
the partial-intercept ratio semantics (0.0 ≡ secure, 1.0 ≡ full attack,
0.3 ⇒ intermediate QBER).

> Educational prototype — the privacy-amplification step is simplified
> (fixed SHA-256 rather than a universal₂ hash sized to estimated entropy and
> leakage), and there is no error-correction/reconciliation stage.
