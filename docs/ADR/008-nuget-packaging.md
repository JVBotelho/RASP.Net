# ADR 008: NuGet Packaging & Package Boundaries

**Date:** 2026-07-03
**Status:** 🟡 Proposed
**Priority:** High — gates everything in Stage 1 and, indirectly, the OWASP submission (ADR 010)
**Builds on:** [ADR 006](006-sink-instrumentation-strategy.md) (the phase A/B/C risk boundary this ADR turns into package boundaries), [ADR 007](007-execution-context.md) (the context layer that ships in the core)

---

## Context

Today the SDK is **source-only**. Adopting it means cloning the repository with submodules and
referencing `.csproj` files directly. Every project targets `net10.0` exclusively, which excludes
the majority of production deployments still on the `net8.0` LTS line. As the roadmap puts it: a
security product nobody can `dotnet add package` is a repository, not a product.

The codebase already has a natural packaging seam. ADR 006 split sink instrumentation into three
phases with very different risk profiles:

- **Phase A** — supported public hooks (`IDbCommandInterceptor`, `DelegatingHandler` +
  `ConnectCallback`, `System.Text.Json` type-info modifiers). Cross-platform, AOT- and
  trim-compatible, no runtime tricks.
- **Phase B** — MonoMod runtime patching of BCL sinks (`FileStream`, `Process.Start`). Fragile
  across runtime versions, incompatible with Native AOT, and reflection-emit-based — behavior
  that AV/EDR products are known to flag.
- **Phase C** — the native CLR profiler (IL rewriting at JIT time). Windows-only, requires
  environment variables to activate, and a bug in it corrupts the process rather than throwing.

If these ship as one package, Phase B and C become silent transitive dependencies of everyone who
just wanted the SQL guard. For a security library that is not an acceptable default: an operator
must be able to state exactly which interception mechanisms run in their process.

Current project inventory relevant to packaging: `Rasp.Core`, `Rasp.Bootstrapper`,
`Rasp.SourceGenerators` (netstandard2.0, currently `IsPackable=false`), seven
`Rasp.Instrumentation.*` projects, and the native profiler. Benchmark and E2E host projects are
already marked non-packable.

## Decision

Publish the managed SDK as NuGet packages whose boundaries follow the ADR 006 risk boundary, and
multi-target the product projects to `net8.0;net10.0`.

### Package map

| Package | Contents | Risk tier |
|:---|:---|:---|
| `Rasp.Net.Core` | `Rasp.Core` (detection engines, `RaspAlertBus`, `RaspContext`) + `Rasp.SourceGenerators` embedded as an analyzer asset | Phase A |
| `Rasp.Net.AspNetCore` | middleware + security headers | Phase A |
| `Rasp.Net.Grpc` | gRPC interceptor + generated-interceptor wiring | Phase A |
| `Rasp.Net.EntityFrameworkCore` | `SqlSinkGuard` | Phase A |
| `Rasp.Net.AdoNet` | ADO.NET diagnostic listener | Phase A |
| `Rasp.Net.HttpClient` | `SsrfGuard` | Phase A |
| `Rasp.Net.SystemTextJson` | `DeserializationGuard` | Phase A |
| `Rasp.Net` | meta-package: `Rasp.Bootstrapper` (`AddRasp()`) + references to the Phase A set above | Phase A |
| `Rasp.Net.RuntimePatching` | MonoMod guards (`PathTraversalGuard`, `CommandInjectionGuard`) | Phase B — **opt-in only** |
| `Rasp.Net.Profiler.Windows` | native profiler binaries + activation docs | Phase C — **prerelease only** |

Rules that make the boundary hold:

- The `Rasp.Net` meta-package **never** references `Rasp.Net.RuntimePatching` or the profiler.
  Installing the default experience pulls in zero runtime patching.
- `Rasp.Net.RuntimePatching` carries a package README and an XML-doc warning stating the AOT
  incompatibility and the AV/EDR flagging risk before the first line of setup instructions.
- `Rasp.Net.Profiler.Windows` publishes only with prerelease version labels until the native test
  harness and Linux port (Stage 4) land. The "advanced preview" label lives in the version, not
  just in prose.
- The `Rasp.Net.` package ID prefix gets reserved on nuget.org before first publish. Assembly
  names and namespaces stay `Rasp.*` — package identity and assembly identity need not match, and
  renaming assemblies would churn every consumer-visible `using` for no gain.

### Multi-targeting `net8.0;net10.0`

All packable product projects move from `<TargetFramework>net10.0</TargetFramework>` to
`<TargetFrameworks>net8.0;net10.0</TargetFrameworks>`. The performance-critical primitives the
engines rely on (`ReadOnlySpan<char>`, `SearchValues<char>`, `SearchValues<string>`) all exist in
net8.0, so the zero-allocation design survives the downgrade. Where net10.0 has a faster path,
it is taken behind `#if NET10_0_OR_GREATER` with the net8.0 code as the tested default. `Rasp.SourceGenerators` stays `netstandard2.0` as Roslyn requires.

Support policy: the package tracks Microsoft's LTS support windows. When net8.0 leaves support,
dropping the TFM is a MAJOR version bump (see [ADR 009](009-versioning-and-release-pipeline.md)).

### Packaging mechanics

Standard, listed once so they land in the same PR: `IsPackable=true` only on product projects,
SourceLink + deterministic builds, symbol packages (`.snupkg`), `PackageReadmeFile`, MIT
`PackageLicenseExpression`, and package-level tags. The signing hook is already wired per ADR
006's addendum; the publish flow that uses it is ADR 009's subject.

## Consequences

### Positive ✅

- Adoption becomes `dotnet add package Rasp.Net` — the Stage 1 exit criterion.
- The risk boundary is visible at install time. An auditor can read a `.csproj` and know whether
  runtime patching is in the process.
- net8.0 targeting reaches the LTS majority instead of only early net10.0 adopters.
- Per-guard packages let minimal deployments (e.g. only `SqlSinkGuard`) avoid dependencies they
  don't use — relevant for trimming and for dependency-review gates in consuming organizations.

### Negative ⚠️

- The CI test matrix doubles: every test run happens per TFM, and net8.0 behavior differences
  (MonoMod in particular) need their own coverage.
- Ten packages to version and publish instead of one — coordination cost, addressed by lockstep
  versioning in [ADR 009](009-versioning-and-release-pipeline.md).
- The README, quick start, and victim-app wiring all assume source reference via submodule and
  need rewriting around package install.
- MonoMod's compatibility story on net8.0 must be validated before Phase B ships for that TFM —
  it may ship net10.0-only at first.

### Mitigations

- Land multi-targeting first and let CI soak before the first publish, so TFM-specific failures
  surface without a shipped package attached.
- Keep the composite/submodule setup (ADR 001) as the *development* story; packages are the
  *consumption* story. The docs split along that line rather than replacing one with the other.
- If MonoMod on net8.0 proves unstable, `Rasp.Net.RuntimePatching` ships `net10.0`-only with the
  limitation documented, rather than delaying the whole Stage 1 release.

## Alternatives Considered

| Alternative | Verdict |
|:---|:---|
| **Single omnibus package** | ❌ Makes MonoMod and profiler bits a transitive dependency of every consumer — exactly the silent-inclusion failure mode this ADR exists to prevent. |
| **Two packages only (core + everything-risky)** | ❌ Simpler, but couples the profiler (Windows-only, prerelease) to MonoMod (cross-platform, closer to stable); their lifecycles diverge immediately. |
| **`netstandard2.0` targeting for maximum reach** | ❌ Loses `SearchValues<T>`, span-based APIs and the source-generator consumption model the engines are built on. .NET Framework is not a target market for this SDK. |
| **net10.0-only (status quo TFM)** | ❌ Excludes the LTS installed base; contradicts the roadmap's stated reason for Stage 1. |
| **Stay source-only, document submodule consumption** | ❌ Status quo. No dependency-scanner visibility, no SemVer contract, no OWASP-reviewable release artifact. |

## Related ADRs

- [ADR 001](001-composite-architecture.md) — the composite/submodule layout stays as the development workflow.
- [ADR 006](006-sink-instrumentation-strategy.md) — defines the Phase A/B/C boundary the package map mirrors.
- [ADR 007](007-execution-context.md) — `RaspContext` ships in `Rasp.Net.Core`.
- [ADR 009](009-versioning-and-release-pipeline.md) — how these packages get versioned, signed and published.
- [ADR 010](010-owasp-incubator-submission.md) — published packages are an implicit maturity signal for the Incubator application.
