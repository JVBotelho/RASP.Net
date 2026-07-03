# ADR 007: Ambient Execution Context (RaspContext)

**Date:** 2026-06-30
**Status:** ✅ Accepted & Implemented
**Priority:** High
**Builds on:** [ADR 006](006-sink-instrumentation-strategy.md) (the source → sink pivot — this ADR supplies the carrier that links the two)

---

## Context

After [ADR 006](006-sink-instrumentation-strategy.md), detection happens at two physically
separate points in the call graph:

1. **Perimeter / source** — the source-generated `{Service}RaspInterceptor` (the real
   production gRPC interceptor, wired via `AddRaspSecurity()` — see [ADR 006](006-sink-instrumentation-strategy.md)'s
   scope-discipline section) and AspNetCore middleware see the *inbound request* and the
   method being invoked.
2. **Sink sensors** — `SqlSinkGuard`, `SsrfGuard`, `PathTraversalGuard`,
   `CommandInjectionGuard`, `DeserializationGuard` and the MonoMod-patched BCL sinks fire deep
   inside the call, at the exact dangerous operation.

The only thing connecting these two points today is a **bare `string context`**. It is threaded
by hand through every layer:

```csharp
DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown");
void AnalyzeCommand(string commandText, string context, bool? shouldBlock = null);
void PushAlert(string threatType, string payload, string context);   // → RaspAlert.Context
```

Concrete values seen in the code are free-text fragments: `"Incoming Request"`,
`"gRPC.BookService/CreateBook"`, `"EF Core Sink"`, `"ADO.NET DiagnosticListener"`. This string is
the *entire* record of "where did this come from" by the time an alert reaches the bus. That has
three structural problems:

1. **No correlation.** When `SqlSinkGuard` blocks a query, nothing ties it back to the gRPC
   method, the HTTP request, the trace id, or the remote caller that originated it. A SOC analyst
   reading `RaspAlert.Context == "EF Core Sink"` cannot answer "which request did this?".
2. **No carrier for taint.** ADR 006's north-star (Phase C taint tracking) requires marking data
   at the source and reading that mark at the sink. There is nowhere to *put* the taint set: a
   `string` cannot carry the per-request state that taint propagation fundamentally needs.
3. **Lossy and inconsistent.** Each call site invents its own context string. There is no schema,
   no request id, no severity ceiling, no policy override — and no way to add one without
   touching every signature again.

The defining property we are missing is an **ambient, per-request execution context** that flows
*with* the logical operation across `async`/`await`, thread-pool hops and the source → sink gap,
without being passed by hand. .NET already gives us the primitive for exactly this: `AsyncLocal<T>`.

---

## Decision

Introduce **`RaspContext`** — an immutable, per-request ambient context object that is
established at the perimeter (source), flows automatically to every sink, and replaces the bare
`string context` as the unit of provenance.

### Shape

```csharp
namespace Rasp.Core.Context;

/// <summary>
/// Per-request ambient security context. Established at a source (gRPC/HTTP entrypoint),
/// flows with the logical call across async boundaries, and is read at every sink.
/// </summary>
public sealed class RaspContext
{
    /// <summary>Stable id correlating every source + sink event for one logical request.</summary>
    public required string CorrelationId { get; init; }

    /// <summary>The entrypoint that created this context, e.g. "gRPC BookService/CreateBook".</summary>
    public required string Source { get; init; }

    /// <summary>Transport-level origin where known (remote IP, user id, trace id).</summary>
    public string? RemoteId { get; init; }
    public string? TraceId { get; init; }

    /// <summary>When this request entered the protected boundary.</summary>
    public DateTime StartedUtc { get; init; }

    public override string ToString() => $"{Source} [{CorrelationId}]";  // back-compat string view
}
```

> **Note:** `RaspContext` carries no taint property. Taint is tracked separately in a
> process-wide `ConditionalWeakTable<string, object>` (`RaspTaintSensor`, see
> [ADR 006](006-sink-instrumentation-strategy.md) addendum), keyed by *string instance
> identity*, not by request. Object identity alone already disambiguates concurrent
> requests (two requests never share the same string instance), so a per-request taint
> carrier on `RaspContext` is unnecessary. The rest of this ADR — ambient flow,
> correlation, orphan contexts — is unaffected.

### Ambient flow via `AsyncLocal`

```csharp
public static class RaspExecutionContext
{
    private static readonly AsyncLocal<RaspContext?> _current = new();

    public static RaspContext? Current => _current.Value;

    /// <summary>Establish context at a source. Returns a scope that clears it on dispose.</summary>
    public static RaspScope BeginScope(RaspContext context)
    {
        _current.Value = context;
        return new RaspScope();   // readonly struct; restores previous value on Dispose
    }
}
```

* **Sources establish it.** The generated `{Service}RaspInterceptor.UnaryServerHandler`
  (the real production gRPC interceptor) and the AspNetCore middleware each build a
  `RaspContext` from the request (method, trace id, remote IP) and open a scope around
  `continuation(...)`. The visible cost is one `AsyncLocal` write at scope entry, but
  because a non-default `ExecutionContext` must then be captured and restored at every `await`
  suspension for the rest of the request, the real cost is paid incrementally across the whole
  async chain, not just once — see "Performance posture" below.
* **Sinks read it in addition to, not instead of, their existing `context` argument.** The
  `string context` parameter on `Guard.AnalyzeX(...)` methods (`"EF Core Sink"`,
  `"FileStream/OpenHandle"`, `"Outbound HTTP"`, ...) identifies *which sink* fired and is kept
  unchanged — `RaspContext` cannot replace it, because one `RaspContext` is shared by every sink
  that fires within the same request, so it has no way to know which specific sink a given call
  came from. Guards additionally read `RaspExecutionContext.Current` to enrich the alert with
  *request*-level provenance (correlation id, source method, trace id) alongside the existing
  sink-level identity. When `Current` is `null` (a sink reached with no perimeter, e.g. a
  background job), the guard synthesizes a minimal "orphan" context so detection still works — the
  source pivot of ADR 006 explicitly allows sinks to fire without a perimeter.

### Migration of the `string context` parameter

We keep the engines' span-based hot path untouched and migrate **provenance** only — `RaspContext`
is read at exactly one place, the alerting boundary, and never threaded into `Inspect(...)`:

* `IDetectionEngine.Inspect(...)` keeps its `string context` parameter **unchanged in both
  signature and meaning** — the engine is the transport-agnostic "brain" (ADR 006) and must not
  depend on ambient state. Callers keep passing whatever fine-grained identity they already pass
  today (the field name, e.g. `"Title"`, at the perimeter; the sink name, e.g. `"EF Core Sink"`,
  from a Guard) — `RaspExecutionContext.Current` is never substituted in here, since doing so would
  collapse that per-field/per-sink granularity down to one per-request string and make `Inspect`
  results harder to attribute.
* `RaspAlertBus.PushAlert(...)` gains an overload that accepts the `RaspContext` and snapshots its
  structured fields (`CorrelationId`, `Source`, `RemoteId`, `TraceId`) onto `RaspAlert`/
  `RaspAlertEvent`, which are extended with those fields. The legacy string overload remains for
  call sites not yet migrated.

```
   SOURCE (perimeter)                          SINK (ground truth)
   ┌────────────────────────┐                  ┌─────────────────────────┐
   │ Generated Interceptor / │ AsyncLocal flow │ SqlSinkGuard / SsrfGuard │
   │ AspNetCore middleware  │ ───────────────▶ │ PathTraversalGuard ...   │
   │ BeginScope(RaspContext)│   (no manual     │ RaspExecutionContext     │
   └────────────────────────┘    threading)    │   .Current  → enrich     │
                                                └─────────────────────────┘
                                                            │
                                                            ▼
                                          RaspAlertBus.PushAlert(context)
                                          → correlated, structured alert
```

### Performance posture

Consistent with the zero-allocation discipline of [ADR 005](005-xss-engine.md):

* The context object is allocated **once per request** at the source, not per inspection. But the
  `AsyncLocal` write is not a one-time cost: once set, every `await` suspension for the rest of the
  request flows a non-default `ExecutionContext`, which is captured and restored on each hop. Clean
  traffic pays the one object allocation plus that recurring per-`await` flow cost — not "one write
  and done".
* `RaspContext` is immutable; it does not carry a taint payload (see the superseded note
  above) so it adds no allocation beyond the object itself.
* Engines and the SIMD hot path are **not** on this path — `RaspContext` carries provenance
  only, never the candidate string, so the `~109 ns` clean-scan number from ADR 005 is unaffected.

**Measured (2026-07-01, `Rasp.Benchmarks.AsyncLocalBenchmarks`, 3 chained `await Task.Yield()` hops
per request — simulates the perimeter → guard span):**

| Method | Mean | Allocated | Ratio |
|---|---:|---:|---:|
| `Baseline_NoContext` (no `AsyncLocal` set) | 1.111 µs | 448 B | 1.00 |
| `WithContext_Active` (`BeginScope` + 3 flowed hops + `.Current` read) | 1.144 µs | 528 B | 1.03 / 1.18 alloc |

The recurring per-`await` flow cost is real but small: **~33 ns total across 3 hops** (~11 ns/hop),
and the only extra allocation is the 80 B `RaspContext` instance itself — `ExecutionContext` capture/
restore of a non-default local does not allocate per hop. Confirms the "likely small" prediction
below without needing to assume it.

---

## Consequences

### Positive ✅
- **Correlation:** every sink alert is now joinable to its originating request, trace and
  caller — for both HTTP (`RaspContextMiddleware`) and gRPC (the generated
  `{Service}RaspInterceptor`, which establishes the scope directly, not via
  `SecurityInterceptor` — that class is a generic fallback used only by benchmarks and was
  never wired into `AddRaspSecurity()`). Verified end-to-end for gRPC by
  `GrpcCorrelationTests` (`Rasp.Instrumentation.Grpc.Tests`): a real handler observes a
  non-null, non-orphan `RaspExecutionContext.Current` with a distinct `CorrelationId` per
  request, through the actual `AddRaspSecurity()`-registered pipeline.
- **Correlation model reused by Phase C's telemetry:** `RaspContext`'s correlation id/source
  fields let taint alerts (raised from `RaspTaintSensor`, not from `RaspContext` itself — see
  the superseded note above) be joined back to the originating request the same way any
  other sink alert is.
- **No manual threading:** sinks stop receiving a hand-passed `context` argument; ambient flow is
  automatic across `async`/`await`.
- **Richer, schematized alerts:** `RaspAlert` carries structured provenance instead of free text.
- **Engines unchanged:** the span-based `IDetectionEngine` brain stays transport- and context-agnostic.

### Negative ⚠️
- **`AsyncLocal` cost:** not a one-off write — once `BeginScope` sets a non-default
  `ExecutionContext`, every subsequent `await` in the request's logical call chain captures and
  restores it. Measured at ~11 ns/hop and no per-hop allocation (see "Performance posture" above) —
  small relative to inspection cost, confirmed rather than assumed.
- **Orphan sinks:** sinks reached without a perimeter (background jobs, timers) have no source
  context and must synthesize one — provenance is weaker there.
- **Migration surface:** every `PushAlert` / guard call site is touched, and `RaspAlert` schema
  changes ripple to the bootstrapper's alert consumer.

### Mitigations
- Keep the legacy `string` overloads (`Inspect`, `PushAlert`) so migration is incremental and the
  source generator / existing tests keep compiling.
- `RaspContext.ToString()` is the canonical bridge to the old string contract — one line per site.
- Guards synthesize a deterministic orphan context (`Source = "orphan:<sink>"`) so detection and
  blocking never depend on a perimeter being present (faithful to the ADR 006 sink pivot).
- Taint tracking's own cost (the `ConditionalWeakTable` in `RaspTaintSensor`) is independent
  of `RaspContext` and only materializes when a taint-emitting source actually marks data.

---

## Alternatives Considered

| Approach | Why not |
|:---|:---|
| **Keep the bare `string context`** | No correlation, no taint carrier; blocks ADR 006 Phase C. |
| **Pass `RaspContext` explicitly through every call** | Cannot extend the public signature of the BCL methods Phase B patches (`FileStream` ctor, `Process.Start()`) regardless of patching tool — there is no parameter slot to add it to; defeats the point. |
| **`ThreadLocal` / `ThreadStatic`** | Does not flow across `await`; loses context on the first thread-pool hop — fatal for async sinks. |
| **`Activity` / `DiagnosticSource` baggage only** | Good for tracing, but not designed to carry a mutable taint set or RASP policy; we read `Activity` for `TraceId` and keep our own context for the rest. |
| **DI-scoped service** | No DI scope exists at MonoMod-patched BCL sinks; ambient `AsyncLocal` is the only carrier that reaches them. |

---

## Related ADRs
- **[ADR 006](006-sink-instrumentation-strategy.md):** the source → sink pivot — `RaspContext` is the carrier that links a perimeter source to a ground-truth sink, and the home for Phase C taint state.
- **[ADR 005](005-xss-engine.md):** zero-allocation discipline — context is allocated once per request, off the SIMD hot path.
- **[ADR 002](002-detection-engine-evolution.md):** the entrypoint, reframed by ADR 006 as a taint *source*, is where `RaspContext` is established.
