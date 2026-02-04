# ADR 004: Memory Disclosure Protection Strategy (Lean Sentinel)

**Status:** Accepted (Deferred Implementation)
**Date:** February 4, 2026
**Priority:** Medium

## Context
The evolution of RASP.Net for .NET 10 requires addressing Memory Disclosure vulnerabilities (the “Bleed” family, e.g., Heartbleed, MongoBleed). Although .NET is a managed runtime, modern high-performance patterns—such as `ArrayPool<T>`, aggressive `Span<T>` slicing, and P/Invoke calls to native libraries (e.g., SQLite)—reintroduce the risk of unintentionally leaking uninitialized or stale memory from previous requests. Such leaks may expose PII, authentication tokens, or secrets at response boundaries.

## Research & Investigation
Multiple detection strategies were prototyped and evaluated. The following conclusions were reached:

| Technique | Result | Reason for Rejection |
| :--- | :---: | :--- |
| **Canary Poisoning** | ❌ Rejected | `ArrayPool<T>.Shared` is static and sealed; no safe hook point exists. Runtime patching (e.g., Harmony) introduces instability and unacceptable performance risk. |
| **Statistical Z-Score** | ❌ Rejected | Legitimate API payload variability leads to >30% false positives. Small but critical leaks (e.g., short tokens) are statistically invisible. |
| **Shannon Entropy** | ❌ Rejected | Cannot distinguish legitimate high-entropy data (JWTs, encrypted blobs, compression artifacts) from leaked secrets without expensive semantic parsing. |
| **DB Column Validation** | ❌ Rejected | Native driver failures typically surface as crashes or data corruption, not silent over-reads into managed buffers. |

**Conclusion:** Heuristic or probabilistic memory disclosure detection inside a managed RASP introduces unacceptable false positives, performance overhead, and operational noise.

## Decision: The Lean Sentinel
RASP.Net will adopt the **Lean Sentinel** strategy.

Instead of acting as a global memory custodian, the RASP will function as a deterministic **Response Boundary Guard** within the gRPC interceptor layer. The Lean Sentinel focuses exclusively on binary, contract-violating signals that strongly indicate catastrophic memory disclosure, avoiding probabilistic inference or deep content inspection.

### Core Components

1.  **Response Size Hard Limits**
    * Enforce explicit, contract-aware maximum response sizes per endpoint.
    * Block responses that exceed predefined hard caps (e.g., a `GetBook` RPC returning tens of megabytes).
    * *This mechanism detects mass memory disclosure scenarios analogous to Heartbleed-style over-reads.*

2.  **High-Fidelity Pattern Scanning**
    * Use .NET 10 `SearchValues<byte>` for SIMD-accelerated scanning.
    * Scan only for **explicitly forbidden, immutable secret prefixes** (e.g., `sk_live_`, `xoxb-`) that must never appear in outbound responses.
    * *No generic “token detection” or regex-based inference is performed.*

3.  **Debug Artifact Detection**
    * Binary scanning for well-known debug heap patterns (e.g., `0xCDCD`, `0xABAB`).
    * Detection in production indicates a critical build or memory management flaw, not an ambiguous security signal.
    * *Results in immediate high-severity alerting.*

4.  **Limited Context Awareness**
    * Context is derived from gRPC metadata and `AsyncLocal` scope.
    * Context-awareness is limited to binary enable/disable decisions (e.g., endpoints explicitly marked as expecting sensitive data).
    * *No runtime semantic inference, DTO parsing, or probabilistic content analysis is performed.*

### Performance & Allocation Goals
* **Overhead:** < 100ns per response.
* **Allocation:** Zero allocations on the hot path.
* All inspections operate directly on `ReadOnlySpan<byte>`.

These constraints align with the performance guarantees established in **[ADR 002](002-detection-engine-evolution.md)**.

## Consequences

### Positive
* **Operational Stability:** Drastically reduced false positives; avoids alert fatigue.
* **Engineering Honesty:** Explicitly acknowledges the limits of managed RASP for memory-level guarantees.
* **Deterministic Behavior:** Binary pass/fail signals instead of probabilistic judgments.
* **Performance Integrity:** Preserves the project’s high-performance positioning.

### Negative
* **Partial Coverage:** Does not detect semantic PII leaks (e.g., names, addresses) or misplaced high-entropy values without fixed binary markers.
* **Deferred Semantics:** Rich semantic validation is postponed until compile-time mechanisms are available.

## Relationship to Other ADRs
* **[ADR 002 – Detection Engine Evolution](002-detection-engine-evolution.md):** Semantic memory validation is explicitly deferred to **Phase 3 (Source Generators)**, where compile-time knowledge enables schema-aware, zero-reflection, zero-heuristic enforcement.
* **[ADR 003 – Native Integrity Guard](003-native-integrity-guard.md):** Lean Sentinel does not attempt to replace native memory safety mechanisms or kernel-level instrumentation.

## Implementation Plan
* Not implemented.
* Targeted for after stabilization of core SQLi/XSS detection engines.
* Implementation priority remains secondary to maintaining correctness, determinism, and performance of existing protections.

## Summary
This ADR intentionally rejects complex runtime heuristics for memory disclosure detection in favor of simple, deterministic boundary checks with high signal-to-noise ratio. The Lean Sentinel provides a pragmatic safety net against catastrophic memory leaks while preserving the architectural integrity, performance guarantees, and credibility of RASP.Net.