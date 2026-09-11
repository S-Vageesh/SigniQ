export interface ScenarioResult {
  scenario: string
  intercept_ratio: number
  raw_key_length: number
  matching_bases_count: number
  sifted_key_length: number
  qber: number
  dynamic_threshold: number
  is_authentic: boolean
  threat_flagged: boolean
  first_divergence: number | null
  derived_secret?: string
  hmac_tag?: string
  hmac_valid?: boolean
  note: string
}

export interface RunResponse {
  run_id: number
  results: ScenarioResult[]
  authenticated_message: string | null
}

export interface SweepResponse {
  run_id: number
  sweep: ScenarioResult[]
}

export interface ProgressEvent {
  type: 'progress'
  run_id: number
  scenario: string
  processed: number
  total: number
  sifted: number
  mismatches: number
  qber: number
  threshold: number
}

export interface ResultEvent {
  type: 'result'
  run_id: number
  result: ScenarioResult
}

export interface DoneEvent {
  type: 'done'
  run_id: number
}

export type RunEvent = ProgressEvent | ResultEvent | DoneEvent

const BASE = import.meta.env.DEV ? '' : window.location.origin

async function jsonFetch<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const err = await res.json()
      if (err?.error) msg = err.error
    } catch {
      /* keep default */
    }
    throw new Error(msg)
  }
  return res.json() as Promise<T>
}

export function startRun(params: {
  key_length?: number
  base_threshold?: number
  intercept_ratio?: number
  message?: string
  seed?: number
  pace_ms?: number
}): Promise<RunResponse> {
  return jsonFetch<RunResponse>('/api/run', params)
}

export function runSweep(params: {
  intercept_ratios: number[]
  key_length?: number
  base_threshold?: number
  seed?: number
}): Promise<SweepResponse> {
  return jsonFetch<SweepResponse>('/api/simulate', params)
}

export function healthCheck(): Promise<string> {
  return fetch(`${BASE}/api/health`).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    return r.text()
  })
}

// ---------------- QDS Signature Lab ----------------

export interface QdsSetupResponse {
  qubit_count: number
  lambda: number
  key_commitment: string
  theory_forgery_probability: number
}

export interface TeleportSample {
  position: number
  bell_outcome: number
  correction: string
  raw_bit: number
  corrected_bit: number
}

export interface QdsSignResponse {
  nonce: number
  signature_hex: string
  teleport_sample: TeleportSample[]
  qubit_count: number
  lambda: number
  theory_forgery_probability: number
  initial_verification_accepted: boolean
}

export interface VerificationReport {
  accepted: boolean
  verdict: 'acc1' | 'acc0' | 'rej'
  match_ratio: number
  mismatches: number
  total_positions: number
  reason: string
}

export interface QdsOutcome {
  label: string
  kind: string
  report: VerificationReport
  description: string
  claimed_message: string
  charlie_agrees?: boolean
}

export interface QdsEventRow {
  ts: string
  kind: string
  label: string
  accepted: boolean
  detail: string
}

export interface ForgeryAnalysis {
  qubit_count: number
  lambda: number
  trials: number
  monte_carlo_probability: number
  theory_probability: number
  by_lambda: { lambda: number; theory: number }[]
}

export const qdsApi = {
  setup: (qubitCount: number, lambda: number): Promise<QdsSetupResponse> =>
    jsonFetch<QdsSetupResponse>('/api/qds/setup', {
      qubit_count: qubitCount,
      lambda,
    }),
  sign: (message: string, seed?: number): Promise<QdsSignResponse> =>
    jsonFetch<QdsSignResponse>('/api/qds/sign', { message, seed }),
  verify: (message: string, signatureHex: string, nonce: number): Promise<QdsOutcome> =>
    jsonFetch<QdsOutcome>('/api/qds/verify', {
      message,
      signature_hex: signatureHex,
      nonce,
    }),
  attacks: (tamperFraction?: number): Promise<QdsOutcome[]> => {
    const q = tamperFraction !== undefined ? `?tamper_fraction=${tamperFraction}` : ''
    return fetch(`${BASE}/api/qds/attacks${q}`).then((r) => r.json())
  },
  forgeryAnalysis: (): Promise<ForgeryAnalysis> =>
    fetch(`${BASE}/api/qds/forgery-analysis`).then((r) => r.json()),
  metrics: (trials?: number, seed?: number): Promise<MetricsReport> => {
    const params = new URLSearchParams()
    if (trials !== undefined) params.set('trials', String(trials))
    if (seed !== undefined) params.set('seed', String(seed))
    const q = params.toString() ? `?${params.toString()}` : ''
    return fetch(`${BASE}/api/qds/metrics${q}`).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      return r.json()
    })
  },
  events: (): Promise<{ events: QdsEventRow[] }> =>
    fetch(`${BASE}/api/qds/events`).then((r) => r.json()),
}

// ---------------- Performance evaluation (Lap 2 deliverable) ----------------

export interface ConfusionCounts {
  true_negatives: number
  false_positives: number
  true_positives: number
  false_negatives: number
}

export interface TimingStats {
  samples: number
  mean_sign_us: number
  mean_verify_us: number
  mean_attack_us: number
  mean_setup_us: number
}

export interface TeleportMetrics {
  trials: number
  qubit_count: number
  lambda: number
  confusion: ConfusionCounts
  empirical_forgery_probability: number
  theoretical_forgery_probability: number
  timing: TimingStats
}

export interface ClassDetection {
  detected: number
  missed: number
}

export interface SixStateMetrics {
  trials: number
  n_pulses: number
  confusion: ConfusionCounts
  detection_by_class: Record<string, ClassDetection>
  timing: TimingStats
}

export interface MetricsReport {
  teleport: TeleportMetrics
  six_state: SixStateMetrics
  notes: string[]
}
