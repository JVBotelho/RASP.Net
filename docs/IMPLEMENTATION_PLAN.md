# 🧩 Implementation Plan — Sinks, Detections & Versioning

> Companion to [ROADMAP.md](ROADMAP.md) (product vision) and
> [ADR 006](ADR/006-sink-instrumentation-strategy.md) (architecture).
> This document is the **execution plan**: what to build, in what order, and under which version.

**Baseline:** `v1.0.5` — engines (SQLi, XSS) + source-generated gRPC interceptors + native
Windows guard + telemetry/alert infrastructure are in place. The detection *brain* is done;
the **sink instrumentation layer** is not.

---

## 0. Architectural framing

Per [ADR 006](ADR/006-sink-instrumentation-strategy.md), detection moves from the **entrypoint**
to the **sink**. Engines are reused unchanged (`IDetectionEngine`, span-based). Every release
below adds a **sink sensor** that captures ground-truth data and calls an engine. The gRPC
interceptor stays as an optional perimeter/taint-source layer.

Each new sink sensor follows the same contract:

1. Capture data as close to the dangerous call as possible (command text, path, URI, type name).
2. Run it through an `IDetectionEngine` (existing or new).
3. Honor `RaspOptions.BlockOnDetection` (block vs. audit).
4. Emit `IRaspMetrics.RecordInspection` / `ReportThreat` **and** `RaspAlertBus.PushAlert`.

---

## 1. Foundation fixes (ship together with the first sink — `v1.1.0`)

These are end-to-end wiring gaps that exist *today* and must be closed before/with the first
sink, otherwise even existing detections don't behave correctly.

| # | Gap | Fix | File(s) |
|:--|:----|:----|:--------|
| F1 | `BlockOnDetection` / audit mode ignored — interceptors always `throw` | Read the option before throwing; in audit mode, log + alert + metric, do **not** throw | generated interceptor template in `Rasp.SourceGenerators/GrpcServiceInterceptorGenerator.cs`; `SecurityInterceptor` |
| F2 | `IRaspMetrics` never called on hot paths | Inject `IRaspMetrics`; call `RecordInspection` always and `ReportThreat` on detection | interceptor template; sink sensors |
| F3 | `RaspAlertBus` has no consumer — alerts dropped | Register a default `IHostedService` consumer (structured log + metric sink; pluggable) | `Rasp.Bootstrapper/RaspDependencyInjection.cs` |
| F4 | `CompositeDetectionEngine` not in production DI — `SecurityInterceptor` gets SQL only (no XSS) | Register `CompositeDetectionEngine` as the `IDetectionEngine` | `Rasp.Bootstrapper/RaspDependencyInjection.cs` |
| F5 | Empty `Rasp.Instrumentation.Grpc.Tests` + commented-out benchmarks | Add integration tests; re-enable `InterceptorBenchmarks` / `SourceGeneratorBenchmarks` in CI | tests + `Rasp.Benchmarks` |

**Definition of done for F1–F4:** an integration test proving (a) audit mode logs without
throwing, (b) a threat increments `rasp.threats.total`, (c) an alert is consumed, (d) XSS is
detected through the `IDetectionEngine` path.

---

## 2. Sink roadmap (mapped to OWASP Top 10 2021)

Ordering anchored on the OWASP Top 10 (best fit for sink-based RASP — the injection/integrity/
SSRF families). The API Top 10 (2023) is largely access-control (BOLA, broken object/property
auth) which a sink RASP can only *partially* cover; noted where relevant.

| Sink / Detection | OWASP | Engine | Phase ([ADR 006](ADR/006-sink-instrumentation-strategy.md)) | Target version |
|:---|:---|:---|:---|:---|
| **SQL** (EF Core interceptor + ADO `DiagnosticListener`) | A03 Injection | reuse `SqlInjectionDetectionEngine` | A | **v1.1.0** |
| **Command Injection** (`Process.Start`) | A03 Injection | new `CommandInjectionDetectionEngine` | B (Harmony) | **v1.2.0** |
| **Path Traversal** (`File.*`, `FileStream`) | A03 / A01 | new `PathTraversalDetectionEngine` | B (Harmony) | **v1.2.0** |
| **SSRF** (`HttpClient` `DelegatingHandler`) | A10 SSRF | new `SsrfDetectionEngine` (URL/host allowlist + private-IP/metadata block) | A | **v1.3.0** |
| **Insecure Deserialization** (`BinaryFormatter`, JSON `TypeNameHandling`, `SerializationBinder`) | A08 Integrity Failures | new `DeserializationGuard` (type allow/deny) | A + B | **v1.3.0** |
| **LDAP Injection** (`DirectorySearcher`) | A03 Injection | new `LdapInjectionDetectionEngine` | B (Harmony) | **v1.4.0** |
| **XXE** (`XmlReader` / `XmlDocument.Load`) | A03 / A05 | policy guard (disable DTD/external entities) | B (Harmony) | **v1.4.0** |
| **Memory / Response Disclosure** (Lean Sentinel — [ADR 004](ADR/004-memory-disclosure-protection.md)) | A04 / A09 | outbound response sensor + secret pattern scan | A | **v1.5.0** |
| **Taint Tracking** (source→sink propagation) | cross-cutting (slashes false positives) | CLR profiler + taint engine | C (Profiler) | **v2.0.0** |

> **OWASP coverage note for the portfolio README:** by completing v1.1–v1.5 the project
> addresses A03 (Injection), A08 (Integrity/Deserialization), A10 (SSRF), plus A05
> (Misconfiguration — security headers, already shipped) and A04/A09 (Lean Sentinel +
> telemetry). A01/A02/A06/A07 are out of scope for a sink-based RASP and should be stated as
> such explicitly.

### Per-sink template (definition of done)

For every sink sensor: (1) capture point identified & documented; (2) engine with SIMD
pre-filter where applicable; (3) unit tests with OWASP payload corpus; (4) BenchmarkDotNet hot
path (clean traffic) measured; (5) red-team script under `attack/`; (6) audit + block modes
tested; (7) ADR if the mechanism is novel (e.g., first Harmony patch = new ADR).

---

## 3. Versioning strategy (modern OSS .NET)

**Current state:** `<Version>1.0.5-elite</Version>` hard-coded in each `.csproj`; no git tags;
no Central Package Management; observable package drift (`Google.Protobuf` 3.33.5 vs 3.33.2).
The `-elite` suffix is not a valid SemVer pre-release ordering token.

**Adopt:**

1. **MinVer** for tag-driven SemVer — version comes from the latest git tag; no manual
   `<Version>` edits. (Alternative: Nerdbank.GitVersioning / `nbgv` if richer build metadata is
   wanted. Avoid GitVersion — heavier and older.)
   - Add `MinVer` `PackageReference` (PrivateAssets=all) and **delete** every hard-coded
     `<Version>` from the `.csproj` files.
   - Tag releases: `git tag v1.1.0` → produces `1.1.0`; commits after a tag auto-become
     `1.1.1-alpha.0.N` pre-releases.
2. **Drop the `-elite` suffix**; use standard pre-release labels `-alpha` / `-beta` / `-rc`.
   Keep "Elite" as marketing copy in the README, not in the version string.
3. **Central Package Management** — add `Directory.Packages.props` at repo root, move all
   `PackageReference` versions there (`<PackageVersion .../>`), set
   `<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>`. Fixes the drift.
4. **Centralize product metadata** — `<Version>` removed; shared props already live in
   `src/Directory.Build.props`.
5. **Conventional Commits** + automated **CHANGELOG.md** (e.g., `git-cliff`). The git history
   already uses `feat:` / `chore:` / `fix:` — formalize it and enforce in CI.
6. **Release flow** — tag on `main` → CI builds, runs tests + benchmarks regression gate →
   publishes NuGet + GitHub Release with generated notes. Keep the `develop` + `feature/*`
   branch model already in use.
7. **SemVer discipline for a security library:** any change that loosens a default or changes
   block→audit behavior is a **MINOR at least**; removing/renaming a public API or changing the
   activation model (e.g., profiler in v2) is **MAJOR**. Detection-rule additions are MINOR
   (they can change runtime behavior); pure fixes are PATCH.

### Version → feature map

| Version | Theme | Contents |
|:--|:--|:--|
| **v1.1.0** | *Wired* | Foundation fixes F1–F5 + **SQL sink sensor** (EF/ADO). First true sink. |
| **v1.2.0** | *Process & Files* | Harmony layer introduced + **Command Injection** + **Path Traversal** sinks. New ADR for Harmony. |
| **v1.3.0** | *Outbound & Objects* | **SSRF** (HttpClient handler) + **Deserialization** guard. |
| **v1.4.0** | *Directory & XML* | **LDAP** + **XXE** sinks. |
| **v1.5.0** | *Lean Sentinel* | Memory/response disclosure sensor + secret scanning ([ADR 004](ADR/004-memory-disclosure-protection.md)). |
| **v2.0.0** | *Taint* | CLR profiler + source→sink taint tracking. Breaking: new activation model. |

---

## 4. Suggested sequencing

```
v1.1.0  ──► Foundation fixes (F1–F5) + SQL sink            [Phase A]
            └─ unblocks correct audit/block, metrics, alerts for ALL detections
v1.2.0  ──► Harmony host + Command Injection + Path Traversal   [Phase B]
v1.3.0  ──► SSRF + Deserialization                          [Phase A + B]
v1.4.0  ──► LDAP + XXE                                       [Phase B]
v1.5.0  ──► Lean Sentinel (response/memory)                 [Phase A]
v2.0.0  ──► Profiler + Taint tracking                       [Phase C]  ← portfolio centerpiece
```

**First actionable step:** implement F1–F4 (they are pure wiring, no new concepts) and the SQL
sink sensor as `v1.1.0`. This is the smallest change that turns the project from
"entrypoint scanner" into "RASP with a real sink", and it makes every existing detection behave
correctly (audit mode, metrics, alerts).
