# ADR 006: Sink Instrumentation Strategy (Entrypoint → Sink Pivot)

**Date:** 2026-06-22
**Status:** ✅ Accepted
**Priority:** Critical
**Supersedes scope of:** [ADR 002](002-detection-engine-evolution.md) (repositions the gRPC interceptor as a *perimeter source*, not the detection core)

---

## Context

Up to `v1.0.5`, all detection happens at the **entrypoint**: a gRPC interceptor (runtime
or source-generated) walks every `string` field of an inbound Protobuf message and runs it
through the detection engines (`SqlInjectionDetectionEngine`, `XssDetectionEngine`).

This is closer to an **embedded WAF / input-validation layer** than to a true RASP. It has
three structural weaknesses:

1. **False positives by design.** A field that legitimately contains `'; DROP TABLE` (a blog
   post about SQL injection, a code snippet, a chat message) is flagged even if that string
   never reaches a database. The entrypoint cannot know whether the data is *used* dangerously.
2. **Framework coupling.** Detection lives inside a gRPC interceptor. Every new transport
   (HTTP REST, message queue, background job, gRPC streaming) needs its own interceptor. The
   gRPC layer only exists today because the target app (`LibrarySystem.*`) happens to be gRPC.
3. **No ground truth.** The entrypoint sees *candidate* attack strings. It never sees the
   actual SQL command text, the actual file path, or the actual process arguments that the
   application is about to execute.

The defining property of a **RASP** (vs. a WAF) is that it instruments the **sink** — the exact
moment a potentially dangerous operation is invoked — where it has full context and can make a
high-confidence allow/block decision.

> **Key realization (issue raised by the maintainer):** "gRPC was only implemented because the
> target app uses it; for a RASP it shouldn't matter, since we analyze at the sink, not at the
> entrypoint." This ADR formalizes that correction.

### What is reusable

The detection engines are already **transport-agnostic**: they only accept
`ReadOnlySpan<char>` via `IDetectionEngine`. They are the *brain* and can be reused unchanged at
any sink. The pivot is **not** a rewrite of the engines — it is a new **instrumentation layer**
that feeds them ground-truth data from the sinks.

---

## Decision

Adopt a **sink-centric architecture** with three concentric layers, delivered in phases.
Detection logic stays in the engines; each layer is just a different *sensor* that calls
`IDetectionEngine.Inspect(...)` with data captured as close to the dangerous operation as
possible.

```
        ┌──────────────────────────────────────────────────────┐
        │  Perimeter (optional)  — gRPC / HTTP entrypoint scan   │  ← taint SOURCE, defense-in-depth
        ├──────────────────────────────────────────────────────┤
        │  SINK SENSORS (the RASP core)                          │  ← ground-truth detection + blocking
        │    SQL · Command · Path · SSRF · Deserialization ·     │
        │    LDAP · XXE · Reflection/Assembly load               │
        ├──────────────────────────────────────────────────────┤
        │  Detection Engines (IDetectionEngine, span-based)      │  ← unchanged "brain"
        └──────────────────────────────────────────────────────┘
```

### Sink instrumentation mechanisms (phased)

.NET offers several ways to observe/intercept a sink. We deliberately layer them from
"supported & blockable now" to "elite & framework-independent later".

#### Phase A — Managed first-class sensors (supported, AOT/trim-friendly, blockable)

Use the hooks the BCL and popular libraries already expose. No IL rewriting.

| Sink | Mechanism | Block? |
|:---|:---|:---:|
| SQL (EF Core) | `IDbCommandInterceptor.ReaderExecuting` — read `CommandText`, throw to block | ✅ |
| SQL (raw ADO.NET) | `DiagnosticListener` `SqlClientDiagnosticListener` (`WriteCommandBefore`) | ⚠️ observe |
| Outbound HTTP / SSRF | `DelegatingHandler` on `HttpClient` — inspect target URI, throw to block | ✅ |
| Deserialization | `JsonConverter` / `SerializationBinder` policy hooks | ✅ |

**Why first:** zero runtime hacks, works under Native AOT and trimming, and the EF/HttpClient
hooks can *block*, not just observe. Covers the highest-frequency OWASP injection sinks.

#### Phase B — Runtime patching via Harmony (broad coverage, opt-in)

For sinks with **no** first-class hook, patch the methods at startup using `Lib.Harmony`
(prefix patch that can `throw` to block):

`Process.Start`, `File.Open` / `File.ReadAllText` / `FileStream` (path traversal),
`Assembly.Load` / `Activator.CreateInstance` (unsafe reflection),
`BinaryFormatter.Deserialize` / `LosFormatter` (legacy deserialization),
`DirectorySearcher` / `DirectoryEntry` (LDAP), `XmlReader` / `XmlDocument.Load` (XXE).

**Trade-offs:** fragile across runtime versions, not Native-AOT compatible, reflection-emit
based (can be flagged by AV/EDR). Therefore **opt-in** and disabled under AOT.

#### Phase C — CLR Profiler + Taint Tracking (the "elite" north star)

A native `ICorProfilerCallback` that rewrites IL on JIT (`SetILFunctionBody`) to inject managed
sensor calls, activated via `CORECLR_ENABLE_PROFILING` / `CORECLR_PROFILER` — the same approach
used by Contrast, Datadog ASM and Dynatrace. This is what enables true **taint tracking**:
mark data at the source (entrypoint), propagate the taint flag through the program, and alarm
**only** when tainted data reaches a sink in a dangerous position. This is the feature that
distinguishes a real RASP from a WAF and is the standout portfolio artifact. We already ship a
native C++ component ([ADR 003](003-native-integrity-guard.md)), so the native tooling is not
new ground.

### Repositioning the entrypoint layer

The gRPC interceptor (and any future HTTP middleware) is **retained** as an optional
**perimeter / taint-source** layer for defense-in-depth and early rejection of obvious garbage —
but it is no longer the place where authoritative detection happens.

---

## Consequences

### Positive ✅
- **Far fewer false positives:** detection fires only when dangerous data actually reaches a sink.
- **Framework-agnostic:** one SQL sensor protects gRPC, HTTP, jobs and any caller of EF/ADO.
- **Real RASP semantics:** ground-truth context (actual command, path, URI) at the decision point.
- **Engines unchanged:** the span-based `IDetectionEngine` is reused as-is.

### Negative ⚠️
- **New surface area:** sink sensors must be maintained per library/runtime version.
- **Harmony fragility & AOT gap:** Phase B cannot run under Native AOT.
- **Profiler complexity:** Phase C is a significant native + taint-propagation effort.

### Mitigations
- Phase A covers the majority of OWASP injection sinks with fully supported APIs.
- Phase B is opt-in via `RaspOptions` and auto-disabled when AOT is detected.
- Each phase ships independently behind feature flags; the engines and perimeter keep working
  if a sink sensor is disabled.

---

## Alternatives Considered

| Approach | Why not (alone) |
|:---|:---|
| **Keep entrypoint-only scanning** | High false positives; not a true RASP; framework-coupled. |
| **DiagnosticSource only** | Observe-only for most sinks; cannot reliably block. |
| **Harmony only** | Broad but fragile and AOT-incompatible; poor fit as the sole strategy. |
| **Profiler only (skip A/B)** | Huge upfront cost; delays all OWASP coverage; high risk for v1.x. |

---

## Related ADRs
- **[ADR 002](002-detection-engine-evolution.md):** engine evolution — gRPC interceptor reframed here as a perimeter source.
- **[ADR 004](004-memory-disclosure-protection.md):** Lean Sentinel = an *outbound/response* sink sensor; fits Layer "Sink Sensors".
- **[ADR 005](005-xss-engine.md):** the XSS engine remains the reusable brain at any sink emitting markup.
