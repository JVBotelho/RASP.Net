# ADR 006: Sink Instrumentation Strategy (Entrypoint → Sink Pivot)

**Date:** 2026-06-22
**Status:** ✅ Accepted & Implemented (Phase A, Phase B, Phase C v1)
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

#### Phase B — Runtime patching via MonoMod (broad coverage, opt-in)

For sinks with **no** first-class hook, patch the methods at startup using
`MonoMod.RuntimeDetour` (`ILHook`-based IL patch that can `throw` to block):

`Process.Start`, `File.Open` / `File.ReadAllText` / `FileStream` (path traversal),
`Assembly.Load` / `Activator.CreateInstance` (unsafe reflection),
`BinaryFormatter.Deserialize` / `LosFormatter` (legacy deserialization),
`DirectorySearcher` / `DirectoryEntry` (LDAP), `XmlReader` / `XmlDocument.Load` (XXE).

**Trade-offs:** fragile across runtime versions, not Native-AOT compatible, reflection-emit
based (can be flagged by AV/EDR). Therefore **opt-in** and disabled under AOT.

#### Phase C — CLR Profiler + Taint Tracking

A native `ICorProfilerCallback` that rewrites IL on JIT (`SetILFunctionBody`) to inject managed
sensor calls, activated via `CORECLR_ENABLE_PROFILING` / `CORECLR_PROFILER` — the same approach
used by Contrast, Datadog ASM and Dynatrace. This is what enables true **taint tracking**:
mark data at the source (entrypoint), propagate the taint flag through the program, and alarm
**only** when tainted data reaches a sink in a dangerous position. This is the feature that
distinguishes a real RASP from a WAF. We already ship a native C++ component
([ADR 003](003-native-integrity-guard.md)), so the native tooling is not new ground.

#### Addendum (2026-06-30): native implementation design notes

Before any C++ is written, four design questions must be settled — getting these wrong is far
more expensive to discover after `ICorProfilerCallback` is live than before, since profiler bugs
corrupt JIT/runtime state rather than throwing a catchable exception. Researched against current
.NET profiling-API guidance and existing production agents (Datadog, New Relic, Contrast); see
[IL Rewriting Basics](https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/profiling/IL%20Rewriting%20Basics.md),
[ICorProfilerInfo::SetILFunctionBody](https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/profiling/icorprofilerinfo-setilfunctionbody-method),
and [dd-trace-dotnet architecture](https://github.com/DataDog/dd-trace-dotnet).

**1. `SetILFunctionBody` at `JITCompilationStarted`, with tiered compilation disabled.**
`SetILFunctionBody` only works on a function that has never been JIT-compiled and is otherwise
"set it and forget it" — simpler than `ReJIT`, and a good fit since RASP applies instrumentation
once at startup, never toggles it (same pattern as the MonoMod patches in Phase B). The hazard:
under tiered compilation, `JITCompilationStarted` fires more than once per method (tier 0, then
tier 1, possibly with On-Stack Replacement), and if the IL set on the second call differs from the
first, the runtime can misbehave mid-method. Mitigation: set
`DOTNET_TieredCompilation=0` for the profiled process so `JITCompilationStarted` fires exactly once
per method, removing the hazard outright rather than trying to keep two rewrite passes consistent.
This trades a (typically small) startup-time JIT performance cost for correctness — acceptable for
a security-critical rewrite path.

**2. Profiler chaining is mandatory, not optional.** The CLR allows exactly **one**
`ICorProfilerCallback` per process via `CORECLR_PROFILER`. Target applications that already run
Datadog, New Relic, Application Insights, or OpenTelemetry auto-instrumentation — all common in
production — would silently fail to load one of the two profilers, with no clear error pointing at
the conflict — a deployment blocker, not a nice-to-have. Mitigation: ship RASP's native component as a **chainable** profiler from day one
(a thin native loader that can itself host/forward to a configured downstream
`ICorProfilerCallback`, the same pattern Contrast and New Relic use for `.NET Framework` profiler
chaining), or document clearly that RASP must be the sole profiler and provide a startup check that
fails loudly (not silently) if `CORECLR_PROFILER` is already claimed. See
[Profiler conflicts (New Relic)](https://docs.newrelic.com/docs/apm/agents/net-agent/troubleshooting/profiler-conflicts/)
and [Profiler chaining for the .NET Framework agent (Contrast)](https://docs.contrastsecurity.com/en/-net-framework-profiler-chaining.html).

**3. Taint storage: `ConditionalWeakTable<string, object>`, not a string-content map or a
per-request carrier.** .NET strings are immutable and carry no spare field to stash a taint
bit on, so taint must be tracked out-of-band, keyed by *object identity* (not content — two
equal strings are not the same tainted/untainted instance). `ConditionalWeakTable<TKey,
TValue>` is the BCL-idiomatic mechanism for this: it attaches metadata to an existing object
without modifying it, and the entry is collected automatically when the string itself
becomes unreachable — no manual cleanup, no leak from long-lived interned strings.
Implemented in `Rasp.Core.Context.RaspTaintSensor` as a single process-wide table, not
per-request state on `RaspContext` ([ADR 007](007-execution-context.md) originally sketched
a `RaspContext.Taint` property for this; it was dropped as dead code once the process-wide
table shipped, since object identity alone already disambiguates concurrent requests — see
the superseded note in that ADR). The native rewriter never touches taint storage directly,
only calls the managed sensor. See
[`ConditionalWeakTable<TKey,TValue>`](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.conditionalweaktable-2?view=net-10.0).

**4. Interop surface: native IL injects calls into a small, stable managed sensor API —
never raw memory/shared-state interop.** Consistent with how Datadog's `dd-trace-dotnet` and
existing RASP phases keep "the brain" managed: the C++ rewriter's only job is to inject `call`
instructions at chosen IL offsets into a narrow, versioned static API
(e.g. `RaspTaintSensor.MarkTainted(string value)` at sources, `RaspTaintSensor.CheckTainted(string
value)` at sink arguments). All taint logic, the `ConditionalWeakTable`, and propagation rules stay
in C# — testable with the same xUnit harness as every other engine in this codebase. The native
side stays dumb on purpose: smaller surface to get wrong in unmanaged code, and changes to taint
*policy* never require touching C++.

**5. `RaspTaintSensor` AssemblyRef pinning and code signing.** The `DefineAssemblyRef` emitted
by `ResolvePropagateTaintMemberRef` (`RaspProfiler.cpp`) names `Rasp.Core` and pins its
**public key token** (`afPublicKey` not set — `kRaspCorePublicKeyToken` is interpreted as a
token, not the full key, per corhdr.h's `IsAfPublicKeyToken`). Resolving by simple name alone
would let any assembly named `Rasp.Core` already loaded in the AppDomain intercept the injected
`CEE_CALL` (an AssemblyRef-hijack). Strong-naming `Rasp.Core` closes that: the CLR loader
refuses to bind the AssemblyRef to anything whose public key doesn't hash to the pinned token,
regardless of anything else in this codebase.

- **Public-signing, not a real private-key signature, for normal builds.**
  `Rasp.Core.csproj` sets `PublicSign=true` against `RaspCore.pub` (public key only). The
  committed `.pub` produces a build with the correct, stable public key token for every
  dev/CI run; the private key (`RaspCore.snk`, gitignored) is only needed for a release build
  whose signature verifies, and dev/CI builds never need it on disk.
- **Authenticode is an opt-in detective check, not the primary control.** .NET Core/.NET 5+
  does not verify strong-name signatures at assembly load — only the public key token match
  is enforced — so the pin above is real but weaker than it looks. `RaspProfiler.cpp`'s
  `ModuleLoadFinished` checks `Rasp.Core.dll`'s Authenticode signature when
  `RASP_REQUIRE_CORE_AUTHENTICODE=1` (off by default — no release build is signed yet) and
  logs via `OutputDebugStringW` if it's missing or invalid. This can't gate the IL rewrite
  itself: `JITCompilationStarted` for `String.Concat` routinely fires before `Rasp.Core.dll`
  has loaded (`Concat` runs all over the BCL before an app's own reference to `Rasp.Core`
  resolves), so there's no correct point to block on a check whose module usually hasn't
  loaded yet. The CLR's token-based bind rejection remains the preventive control;
  Authenticode adds an independent, after-the-fact signal.
- **A code-signing certificate is an open decision, not a technical blocker.** Most OSS .NET
  projects don't Authenticode-sign at all. Direct CA certificates (OV/EV) require a
  registered business entity and a hardware token per CA/Browser Forum rules, impractical for
  an individual project. [SignPath Foundation](https://signpath.org/) signs qualifying OSS
  projects with a real cert through a managed CI pipeline, but the publisher shown is
  "SignPath Foundation," not this project's identity. Left as a documented, revisitable
  decision rather than pursued now.

**Scope discipline for v1.** Full taint propagation through every string operation in a program
(concatenation, `string.Format`, `Substring`, etc.) is the multi-month effort the "Negative"
section below already warns about. v1 ships narrow on purpose:
- **Mark:** the source-generated `{Service}RaspInterceptor` (`Rasp.SourceGenerators`,
  registered via `AddRaspSecurity()` — the actual production gRPC interceptor, not the
  generic `SecurityInterceptor` fallback used only by benchmarks) calls
  `RaspTaintSensor.MarkTainted` inline, in the same direct-property-access code that
  already scans each string field for threats — no separate reflection pass. Covers
  top-level fields, nested messages, and `repeated string` fields. `RaspContextMiddleware`
  separately marks HTTP query string values. Neither marks the response, route values (not
  yet populated when this middleware runs), or the request body/form (deserialized into
  new string instances downstream, so marking here wouldn't reach them).
- **Propagate:** the native profiler's sole v1 target, `System.String::Concat(string, string)`.
- **Check:** `SqlSinkGuard.AnalyzeCommand` calls `RaspTaintSensor.IsTainted(commandText)` and
  attaches the result to the alert as `[Tainted]` — enrichment for triage, never a gate on
  whether the existing signature-based detection blocks. Gating on taint would turn any of the
  gaps above into a false negative instead of a documented limitation.

Taint can be "lost" across any string operation, HTTP input surface, or sink not listed above —
that's a known, accepted v1 gap, not a silent correctness bug, and the existing ground-truth
sink scanning (Phase A/B) continues to provide defense-in-depth for the data taint tracking misses.

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
- **MonoMod fragility & AOT gap:** Phase B cannot run under Native AOT.
- **Profiler complexity:** Phase C is a significant native + taint-propagation effort.
- **Ground-truth allocation cost:** Phase A sinks (`CommandText`, `Uri`, `Type`) inspect data the
  host framework already materializes, so the span-based engines stay effectively allocation-free
  on the happy path. Phase B's filesystem sink breaks this property: BCL path canonicalization
  (`Path.GetFullPath`, symlink resolution) has no `Span`-based, non-allocating form, so ground-truth
  validation against `allowedRoots` allocates a new string on **every** `FileStream` construction
  process-wide — including framework-internal I/O with no user-controlled input. This is the first
  sink where the ground-truth model is structurally more expensive than the signature-scanning
  model it replaces. Mitigated by a two-stage check (cheap `Span`-based fast-accept for paths that
  are already absolute, separator-clean, and prefix-matched against a trusted root; full allocating
  canonicalization only as the fallback) rather than canonicalizing unconditionally.
  Confirmed against the .NET runtime source: `Path.GetFullPath` has no `Span`-based overload in any
  released version, and a non-allocating `Path.NormalizePath` API has been requested but remains
  unimplemented — see
  [dotnet/runtime#121052](https://github.com/dotnet/runtime/issues/121052). Revisit this trade-off
  if that proposal ships.

  **Measured (2026-07-01, `Rasp.Benchmarks.PathTraversalBenchmarks`, real `FileStream` open against
  a file inside `allowedRoots`):**

  | Method | Mean | Allocated | Ratio |
  |---|---:|---:|---:|
  | `NativeFileStream_NoHook` (baseline, guard bypassed via `ReentrancyGuard`) | 17.13 µs | 240 B | 1.00 |
  | `FileStream_Hooked_FastPath` (already-absolute, root-prefixed path) | 17.49 µs | 240 B | 1.02 / 1.00 alloc |
  | `FileStream_Hooked_SlowPath` (relative path, forces `Path.GetFullPath`) | 17.84 µs | 864 B | 1.04 / 3.60 alloc |

  The two-stage design does what it claims: the fast path adds no allocation over the unhooked
  baseline (240 B → 240 B), while the slow path's canonicalization costs **+624 B per call**
  (240 B → 864 B). Both are dwarfed by the underlying disk/OS `FileStream` open itself (~17 µs), so
  the *relative* overhead is small in absolute time (+2–4%) even on the slow path — but the
  allocation delta is exactly the cost the two-stage check exists to avoid paying unconditionally.

### Measured end-to-end latency under sustained load (2026-07-02)

The numbers below are the ones that matter: real requests, sustained concurrent load, real
backends — not an isolated `Inspect()` call against an artificially cheap baseline. Methodology:
`Rasp.Benchmarks.E2EHost` (real Kestrel; `AddRasp`/`AddRaspEntityFrameworkCore`/
`AddRaspHttpClient`/`RaspRuntimePatching.Initialize` toggled via `RASP_MODE=on|off`, otherwise
identical) driven by `Rasp.Benchmarks.LoadDriver` (25 concurrent workers, 20 s sustained load per
endpoint after a 5 s warmup). Real `cmd.exe` subprocess, real Postgres
(`postgres:16.11-alpine` via Testcontainers — SQLite's single-writer lock would have serialized
concurrent writers and measured SQLite contention instead of RASP), real second-process HTTP
target reached over the host's own LAN IP for SSRF.

| Endpoint | Mode | p50 | p95 | p99 | Mean |
|---|---|---:|---:|---:|---:|
| Path Traversal | RASP off | 851 µs | 1131 µs | 1349 µs | 869 µs |
| Path Traversal | RASP on | 858 µs | 1150 µs | 1404 µs | 879 µs |
| Command Injection | RASP off | 60.76 ms | 87.41 ms | 108.22 ms | 63.28 ms |
| Command Injection | RASP on | 61.50 ms | 85.22 ms | 104.59 ms | 63.43 ms |
| SSRF | RASP off | 299 µs | 452 µs | 756 µs | 396 µs |
| SSRF | RASP on | 306 µs | 498 µs | 914 µs | 330 µs |
| SQL | RASP off | 7.76 ms | 13.61 ms | 16.97 ms | 8.32 ms |
| SQL | RASP on | 7.50 ms | 13.12 ms | 16.50 ms | 8.03 ms |

All four sinks: RASP on vs. off is statistically indistinguishable — differences are within normal
run-to-run noise. For Path Traversal, Command Injection, and SQL this is because the guard's own
cost is small relative to the real I/O it wraps. SSRF is small for a different, more structural
reason: see "SSRF DNS cache" below — `SocketsHttpHandler` connection pooling means the guard's
Layer 2 DNS check fires roughly once per pooled connection, not once per request, so its cost
cannot show up in a per-request p50/p99 measurement against a sustained-load, single-destination
benchmark like this one, regardless of how expensive that check actually is.

No `<5%` p99 SLO claim is made here — that requires a representative production request/response
shape and a real middleware stack, neither of which a single-endpoint synthetic benchmark provides.

### SSRF DNS cache (`RaspOptions.SsrfDnsCacheDuration`)

`RaspHttpClientBuilderFilter`'s Layer 2 (`SocketsHttpHandler.ConnectCallback`) calls
`Dns.GetHostEntryAsync` to defend against DNS rebinding — resolving the destination ourselves
immediately before connecting, rather than trusting a resolution the framework made earlier.
`CachingDnsResolver` (`src/Rasp.Instrumentation.HttpClient/CachingDnsResolver.cs`) wraps
`IDnsResolver` with an opt-in TTL cache, off by default
(`RaspOptions.SsrfDnsCacheDuration = TimeSpan.Zero`). 5 unit tests
(`CachingDnsResolverTests.cs`) cover: no caching at duration zero, reuse within TTL,
case-insensitive host keying, re-resolution after TTL expiry, and independent caching per host.

Layer 2 barely shows up in the end-to-end table above because `SocketsHttpHandler` pools and
reuses the TCP connection to a destination — `ConnectCallback` (and any `IDnsResolver`, cached
or not) only runs when a new connection opens. A call counter confirmed this directly: 30
sequential requests to the same host produced exactly 1 DNS resolution.

Three approaches to isolating the cache's own value — an IP-literal target (skips DNS
entirely), the host machine's own hostname (resolved locally, not a real network round trip),
and a `DelayedDnsResolver` benchmark decorator simulating a 20 ms DNS round trip — all hit the
same wall: a cache only pays off on repeated destinations reusing a *new* connection, and a
sustained-load benchmark against one fixed host never opens enough new connections for that to
show up.

The cache's value is also structurally at odds with its own safety constraint: it's only safe
to enable for a small, fixed set of trusted destinations (see the option's own doc comment),
and repeated calls to a fixed destination already get connection pooling's benefit for free —
the cache is redundant exactly where it's safe to use. It would only help on attacker-
influenceable, ever-changing-destination traffic, which is what the option's doc comment warns
against caching for. The feature ships as documented, off by default, and unit-tested; no
end-to-end number is presented for it, because none was obtained under a realistic, safe
deployment pattern.

### Appendix: isolated per-call guard cost (µ-benchmarks)

The tables in this appendix isolate one guard's `Inspect()`/interceptor call against a baseline
that is often artificially cheap (in-memory SQLite, a mocked HTTP handler, `ReentrancyGuard`-
bypassed hooks) — useful for pinpointing a guard's own fixed cost and for regression-testing that
cost in CI, but the *ratio* they report should not be read as production overhead; see the
end-to-end numbers above for that. Each row compares the real integration
(`RaspDbCommandInterceptor` via EF Core, the `ProcessStartPatch` MonoMod hook, the
`RaspHttpMessageHandler` `DelegatingHandler`) against the same call path with RASP absent:

| Sink | Benchmark | Baseline | With RASP | Δ Time | Δ Allocated |
|---|---|---:|---:|---:|---:|
| Command Injection (`Process.Start`, real subprocess) | `CommandInjectionBenchmarks` | 20.92 ms / 37.5 KB | 20.93 ms / 38.05 KB | +~10 µs (noise-level, 0.05%) | +563 B |
| SQL (EF Core, real SQLite `ExecuteSqlRawAsync`) | `SqlSinkBenchmarks` | 2.72 µs / 1.73 KB | 3.31 µs / 2.43 KB | +585 ns (+22%) | +720 B |
| SSRF (`HttpClient`, terminal handler mocked — no real network) | `SsrfBenchmarks` | 290.3 ns / 1.02 KB | 353.5 ns / 1.09 KB | +63 ns (+22%) | +70 B |

The SQL row is the odd one out: it's the only sink whose overhead (**~585 ns**) is *larger* than
the entire XSS clean-scan cost from ADR 005 (~109 ns) — a 5x gap worth explaining rather than
waving away, since XSS and SQL sink both start from the same "SIMD bailout on rare chars" idea.
Two contributing factors, one fixed, one inherent:

- **Fixed:** `SqlSinkGuard.AnalyzeCommand` was the only one of the five `Rasp.Core.Guard` classes
  using `Stopwatch.StartNew()` to time the call — `Stopwatch` is a reference type, so this heap-
  allocates on every invocation, unlike the other four guards' `Stopwatch.GetTimestamp()` /
  `GetElapsedTime()` static (allocation-free) pattern. Switched to match. Re-measured before/after:
  the allocated-bytes delta (0.70 KB) was byte-identical across both runs, meaning the `Stopwatch`
  object (~32–40 B) was too small a fraction of the total to move the number — the fix is correct
  and strictly better (same behavior, less garbage) but isn't what's driving the gap.
- **Inherent:** `SqlSinkDetectionEngine`'s own bailout set is `SearchValues.Create("-;1'")` — and
  the benchmark's "safe" query (`... WHERE Title = 'Clean Code'`) contains a literal `'`, so unlike
  XSS's clean-scan case it does **not** take the single-pass SIMD exit. It falls through to
  comment-breakout scanning, span normalization, 8 tautology substring checks, and a stacked-query
  scan — genuinely more work than "does this string contain `<script>`-shaped characters," because
  catching tautologies (`OR 1=1`) and stacked queries (`; DROP TABLE`) needs that structure, not
  just a character blocklist. Note the bailout set includes the bare digit `1`, so even a fully
  parameterized EF query (`@p0`, `@p1`, ...) likely takes this same slower path purely from its
  parameter name digits, not from any actual injection risk — a possible future tightening of the
  bailout set, not changed here since narrowing a security-relevant character class needs its own
  scrutiny, not a drive-by edit while chasing a benchmark number.

Same pattern as Path Traversal otherwise: **the relative overhead scales inversely with how much
the underlying operation itself already costs.** Spawning a real OS process is ~21 ms, so RASP's
inspection is statistical noise on top of it. A real disk-backed SQLite command is a few
microseconds, so the guard's own cost becomes a visible fraction — still under a microsecond in
absolute terms. The SSRF path is cheapest in isolation (no real I/O, `MockPrimaryHandler` terminates
the pipeline immediately) so its relative delta (+22%) is the largest of the four, but the absolute
cost (63 ns/request) is negligible next to any real outbound network call. In absolute terms none
of the four sinks is a request-latency concern: even the SQL row's 585 ns, the one case that beats
Phase A's own XSS/SQLi perimeter engine cost (~109 ns, ADR 005), is 200–2000x cheaper than a real
network round trip to an actual database, subprocess, or HTTP endpoint — the sink guards add
low-hundreds-of-ns to low-hundreds-of-B on top of whatever the framework operation itself already
costs, which for every one of these four sinks in production is never as cheap as this benchmark's
isolated baseline.

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
| **MonoMod only** | Broad but fragile and AOT-incompatible; poor fit as the sole strategy. |
| **Profiler only (skip A/B)** | Huge upfront cost; delays all OWASP coverage; high risk for v1.x. |

---

## Related ADRs
- **[ADR 002](002-detection-engine-evolution.md):** engine evolution — gRPC interceptor reframed here as a perimeter source.
- **[ADR 004](004-memory-disclosure-protection.md):** Lean Sentinel = an *outbound/response* sink sensor; fits Layer "Sink Sensors".
- **[ADR 005](005-xss-engine.md):** the XSS engine remains the reusable brain at any sink emitting markup.
