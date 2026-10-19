# AiTM-Phishing-Defense: Module 2 Detection Engine

A defensive, explainable detection framework for Adversary-in-the-Middle (AiTM) phishing and reverse proxy authentication attacks, evaluated on synthetic lab telemetry.

---

## 1. Architecture Overview

Module 2 provides an explainable multi-signal detection pipeline consisting of three decoupled sub-analyzers coordinated through an opt-in composite engine:

1. **Base Redirect & Transition Engine (`AiTMDetector.analyze_event`)**: Evaluates redirect chain topologies, cyclic proxy loops, domain transition complexity, hop counts, divergence against observed chains, and client-reported TLS anomalies.
2. **Transport Certificate Analyzer (`TLSAnalyzer.analyze_event_tls`)**: Inspects transport-layer certificate telemetry (`certificate_telemetry`) for hostname mismatches, wildcard scope compliance (RFC 6125), untrusted self-signed root certificates, expired/not-yet-valid validity dates, and SNI hostname mismatches.
3. **Temporal Session Tracker (`SessionTracker.correlate_event`)**: Tracks sequential synthetic authentication events sharing a `session_id` across sliding correlation windows. Evaluates device identifier transitions, rapid IP changes, network origin transitions (residential/corporate to datacenter ASN), client platform/TLS fingerprint divergence, concurrent session bifurcation, and cryptographic token proof-of-possession binding failures.
4. **Composite Multi-Signal Detector (`AiTMDetector.analyze_event_composite`)**: Unifies redirect heuristics with transport and temporal telemetry into an explainable, namespaced composite result with additive risk scoring.

---

## 2. Detection Signals & Additive Scoring Model

### Heuristic Scoring Principles
* **Uncalibrated Risk Score**: A heuristic composite score between `0.00` and `1.00`, capped at `1.00`. It represents an uncalibrated triage indicator, not an empirical statistical probability.
* **Verdict Threshold**: `risk_score >= 0.50` produces a verdict of `"suspicious"`; scores below `0.50` produce `"benign"`.
* **Investigative Triage State**: Isolated transport or context transitions (e.g. `+0.30` or `+0.25`) deliberately remain below `0.50` to prevent false automated blocks on benign network roaming, requiring corroborating evidence before triggering a suspicious verdict.
* **Namespaced Indicators**: Indicators are prefixed by source subsystem to prevent ambiguity:
  * `base:RULE` (redirect sequence heuristics)
  * `tls:INDICATOR` (transport certificate telemetry)
  * `session:INDICATOR` (temporal context correlation)

### Base Redirect Weights
| Indicator / Rule | Weight | Trigger Condition |
|---|:---:|---|
| `base:SUSPICIOUS_REDIRECT_CYCLE` | `+0.35` | Cyclic redirect loop with $\ge 3$ distinct intermediary hosts (reverse proxy insertion). |
| `base:EXCESSIVE_REDIRECT_COUNT` | `+0.30` | Reported redirect count $> 3$ hops outside standard SSO flow. |
| `base:REPEATED_REDIRECT_HOST` | `+0.25` | Repeated host in sequence outside legitimate SSO `[SP, IdP, SP]` pattern. |
| `base:TLS_ANOMALY` | `+0.25` | Client sensor reports transport-layer anomaly flag. |
| `base:HIGH_TRANSITION_COMPLEXITY` | `+0.20` | Traversal of $\ge 3$ distinct organizational domains without a cycle. |
| `base:ELEVATED_REDIRECT_COUNT` | `+0.15` | Exactly 3 redirect hops outside canonical SSO pattern. |
| `base:REDIRECT_TELEMETRY_DIVERGENCE` | `+0.15` | Reported redirect count inconsistent with observed chain length. |

### Transport Layer Modifiers
| Indicator | Weight | Trigger Condition |
|---|:---:|---|
| `tls:CERT_HOSTNAME_MISMATCH` / `tls:UNTRUSTED_AUTH_HOST` | `+0.30` | Certificate SAN/CN does not match target host; or host not in expected IdP allowlist. |
| `tls:UNTRUSTED_SELF_SIGNED_CERT` | `+0.20` | Certificate is self-signed or from an untrusted root (non-exempt). |
| `tls:CERT_EXPIRED` / `tls:CERT_NOT_YET_VALID` | `+0.15` | Current time falls outside certificate validity window (`not_before`, `not_after`). |
| `tls:SNI_HOST_MISMATCH` | `+0.15` | Client SNI hostname disagrees with negotiated certificate subject. |

### Session & Replay Modifiers
| Indicator | Weight | Trigger Condition |
|---|:---:|---|
| `session:TOKEN_BINDING_FAILURE` | `+0.35` | Cryptographic proof-of-possession binding status reports `failed` or `key_mismatch`. |
| `session:SUSPICIOUS_CONTEXT_MISMATCH` | `+0.30` | Concurrent device identifier mismatch and rapid IP transition ($< 60\,\text{s}$). |
| `session:CONCURRENT_SESSION_BIFURCATION` | `+0.25` | Alternating IP addresses ($IP_1 \to IP_2 \to IP_1 \to IP_2$, $IP_1 \ne IP_2$) across 4 chronological events within $\le 120.0\,\text{s}$. |
| `session:CLIENT_PLATFORM_DIVERGENCE` | `+0.25` | Client OS platform or TLS client fingerprint shifts within active session. |
| `session:DATACENTER_SOURCE_TRANSITION` | `+0.20` | Origin network transitions from residential/corporate ASN to datacenter/hosting ASN. |
| `session:DEVICE_CONTEXT_CHANGED` | `+0.15` | Device identifier changes within active session (without rapid IP transition). |
| `session:RAPID_SOURCE_IP_CHANGE` | `+0.10` | Source IP changes within rapid threshold ($< 60.0\,\text{s}$) on same device. |

---

## 3. Test Suite & Verification Commands

All unit tests and benchmarks run out-of-the-box using the standard Python library:

### Run Full Unit Test Suite (96 Tests)
```powershell
python -m unittest discover -s module2_detection/tests -p "test_*.py"
```

### Run Benchmark v1 (16 Synthetic Redirect Scenarios)
```powershell
python .\module2_detection\evaluate.py
```

### Run Benchmark v2 (24 Multi-Signal Synthetic Scenarios)
```powershell
python .\module2_detection\evaluate_v2.py
```

### Code Style & Whitespace Check
```powershell
git diff --check
```

---

## 4. Synthetic Benchmark Results

### Benchmark v1: Redirect-Engine Baseline vs. Enhanced (16 Cases)
* **Dataset**: 16 handcrafted synthetic authentication events (8 benign, 8 suspicious).
* **Metrics**:
  * Precision: `1.0000` (8/8)
  * Recall: `1.0000` (8/8)
  * F1-Score: `1.0000`
  * False Positive Rate: `0.0000`

### Benchmark v2: Multi-Signal Composite Engine (24 Cases)
* **Dataset**: 24 multi-signal synthetic cases combining redirect paths, certificate telemetry, and temporal context transitions (12 benign, 12 suspicious).
* **Metrics**:
  * Base Detector: Recall `0.6667`, Precision `1.0000`, F1-Score `0.8000` (FN: 4)
  * Composite Detector: Recall `0.8333`, Precision `1.0000`, F1-Score `0.9091` (FN: 2)
  * False Positive Rate: `0.0000` (TN: 12/12)

*Scientific Evaluation Note: Benchmark metrics evaluate deterministic rules against specified synthetic fixtures in an authorized lab environment. They do not constitute empirical proof of detection efficacy on unconstrained real-world traffic.*

---

## 5. Security Principles & Scientific Limitations

1. **No Proof of Token Theft**: Heuristic indicators reflect anomaly patterns in synthetic telemetry. Network transitions (IP roaming, mobile-to-Wi-Fi handover) and device updates occur legitimately; heuristic indicators do NOT prove token theft or replay in isolation.
2. **Zero Credential Exposure**: The detection engine operates strictly on synthetic metadata (`session_id`, `timestamp`, `source_ip`, `device_id`, hostname chains). It never inspects, collects, logs, or stores real passwords, bearer tokens, or session cookies.
3. **Zero Ground-Truth Reliance**: The detector is completely agnostic to evaluation labels; it never references `scenario`, `ground_truth`, or `replay_indicator` to compute verdicts.
4. **Ephemeral State**: `SessionTracker` state is in-memory and non-distributed; it resets upon process restart.

---

## 6. Integration Dependencies & Schema Coordination

### Upstream Schema (`integration/event_schema.json`)
The current shared integration contract requires 10 fields:
* `session_id` (string)
* `timestamp` (ISO-8601 string)
* `auth_result` (string)
* `redirect_count` (integer)
* `redirect_chain` (list of strings)
* `tls_anomaly` (boolean)
* `replay_indicator` (boolean)
* `source_ip` (string)
* `device_id` (string)
* `scenario` (string)

### Optional Extended Telemetry (Module 2)
Module 2 supports optional advanced telemetry fields:
* `asn_type`: `"residential"` | `"corporate"` | `"datacenter"` | `"mobile"`
* `client_platform`: e.g. `"windows"` | `"macos"` | `"linux"` | `"ios"` | `"android"`
* `client_tls_fingerprint`: string (e.g. JA4/JA3 fingerprint)
* `token_binding_status`: `"valid"` | `"failed"` | `"key_mismatch"` | `"supported"`
* `certificate_telemetry`: dictionary with `subject_cn`, `sans`, `issuer_org`, `not_before`, `not_after`, `is_self_signed`, `validation_status`, `sni_hostname`

### Schema Coordination Note
* **Backward Compatibility**: All Module 2 components treat extended telemetry as strictly optional. If upstream modules omit these fields, Module 2 functions normally without raising exceptions or penalizing scores.
* **Coordination Requirement**: To allow the Module 1 event generator or edge sensors to produce synthetic replay events with extended telemetry in shared pipeline runs (`run_pipeline.py`), `integration/event_schema.json` should be coordinated with the integration owner to add optional definitions for these fields without making them required.
