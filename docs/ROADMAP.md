# 🗺️ Product Roadmap

> **Vision:** To engineer the definitive standard for high-performance managed security in .NET — a production-grade OSS RASP with negligible runtime overhead, submitted to OWASP (Incubator → Lab) and, once adoption signals exist, to the .NET Foundation.

This is the long-form companion to the [README roadmap](../README.md#-roadmap). Same stages, more
detail per item. The sequencing principle: **adoption infrastructure (Stages 1–2) deliberately
comes before new detection features (Stage 3)** — a security product nobody can
`dotnet add package` is a repository, not a product.

---

## ✅ Shipped — The Foundation

**Focus:** Ground-truth detection at the sink, zero-allocation engines, Windows integrity.

- **✅ Zero-Allocation Engine:** `SqlInjectionDetectionEngine` and `XssDetectionEngine` operate on
  `ReadOnlySpan<char>` with SIMD acceleration (`SearchValues<T>`, AVX2 / AVX-512 when available).
  Clean traffic passes the source-generated perimeter scan in **~109 ns** — 10.3x faster than the
  reflection-based baseline.
- **✅ Composite Architecture:** Unified "God Mode" debugging via Git Submodules — the SDK is
  developed against a real-world "Victim" application ([ADR 001](ADR/001-composite-architecture.md)).
- **✅ Source Generators:** Roslyn generator emits per-service `{Service}RaspInterceptor` classes
  with direct property access — no reflection, no descriptor lookup at runtime
  ([ADR 002](ADR/002-detection-engine-evolution.md)). The dynamic `IMessage.Descriptor` path
  remains as a fallback.
- **✅ Sink-Centric Pivot ([ADR 006](ADR/006-sink-instrumentation-strategy.md), Phases A & B):**
  detection moved from the entrypoint (embedded-WAF style) to the **sink** — the exact moment the
  dangerous operation executes, where the RASP sees the real SQL text, file path, process
  arguments, or target URI.
    - *Phase A (managed, supported hooks):* `SqlSinkGuard` (EF Core `IDbCommandInterceptor`),
      `SsrfGuard` (`DelegatingHandler` + DNS-rebinding-safe `SocketsHttpHandler.ConnectCallback`),
      `DeserializationGuard` (`System.Text.Json` type-info modifier). AOT/trim-friendly, can block.
    - *Phase B (MonoMod runtime patching, opt-in):* `PathTraversalGuard` (`FileStream`/`File.*`),
      `CommandInjectionGuard` (`Process.Start`) — for BCL sinks with no first-class hook.
    - Measured under sustained load (real Kestrel host, real backends): sink overhead is
      **indistinguishable from noise** at p50 and p99 for all four guarded sinks.
- **✅ CLR Profiler + Taint Tracking v1 ([ADR 006](ADR/006-sink-instrumentation-strategy.md), Phase C):**
  native `ICorProfilerCallback` rewriting IL at JIT time (`SetILFunctionBody`) — the same approach
  used by Contrast, Datadog ASM and Dynatrace. v1 scope: taint propagation through
  `String.Concat(string, string)`. Windows-only for now.
- **✅ Ambient Execution Context ([ADR 007](ADR/007-execution-context.md)):** `RaspContext`
  (`AsyncLocal`-carried, immutable, per-request) flows from source to sink, so every alert carries
  a correlation id, source entrypoint, remote id and trace id — a SOC analyst can answer "which
  request caused this block?".
- **✅ Windows Native Guard:** C++ sidecar for PEB manipulation detection and anti-debugging
  ([ADR 003](ADR/003-native-integrity-guard.md)).
- **✅ Security Telemetry:** `RaspAlertBus` with correlated structured alerts, audit (observe-only)
  mode, metrics, and `RaspSecurityHeadersMiddleware` (CSP and friends).

---

## 📦 Stage 1 — Ship It as a Product (NuGet)

**Focus:** Packaging, versioning, multi-targeting. Starts once ADRs 006/007 are finalized and merged.

- [ ] **NuGet packages** for the managed SDK, split along the risk boundary that ADR 006's phases
      already define:
    - The **cross-platform, supported-API core** (Phase A guards + the ADR 007 context layer) is
      the installable product — no runtime hacks, works under Native AOT and trimming.
    - **MonoMod runtime patching** (Phase B) stays a separate, opt-in package — fragile across
      runtime versions, not AOT-compatible, and reflection-emit-based (can be flagged by AV/EDR),
      so it must never be a silent transitive dependency.
    - The **CLR profiler** (Phase C) ships separately as a **Windows-only advanced preview**.
- [ ] **Multi-target `net8.0;net10.0`** so both supported LTS lines can adopt. Today the SDK
      targets .NET 10 only, which excludes the majority of production deployments still on net8.0.
- [ ] **SemVer + release pipeline** — versioned, signed packages published from CI. The signing
      hook is already wired ([ADR 006](ADR/006-sink-instrumentation-strategy.md) addendum point 5);
      what's missing is the tag-triggered publish flow and a versioning policy. Current state:
      `<Version>1.0.5-elite</Version>` is hard-coded per-`.csproj`, no git tags exist, and
      `-elite` isn't a valid SemVer pre-release ordering token. Plan:
    - **MinVer** for tag-driven SemVer (version comes from the latest git tag, no manual
      `<Version>` edits); tagging `v1.1.0` produces `1.1.0`, commits after a tag become
      `1.1.1-alpha.0.N` pre-releases. Drop the `-elite` suffix from the version string itself
      (keep "Elite" as README marketing copy only) and use standard `-alpha`/`-beta`/`-rc` labels.
    - **Central Package Management** (`Directory.Packages.props` at repo root, all
      `PackageReference` versions moved to `<PackageVersion>`,
      `ManagePackageVersionsCentrally=true`) — fixes observed package-version drift across
      projects (e.g. `Google.Protobuf` pinned to different versions in different `.csproj`s).
    - **Conventional Commits** + generated `CHANGELOG.md` (e.g. `git-cliff`) — the git history
      already uses `feat:`/`chore:`/`fix:`, just needs enforcing and wiring to changelog
      generation.
    - **SemVer discipline for a security library:** loosening a default or changing block→audit
      behavior is MINOR at least; removing/renaming a public API or changing the activation model
      (e.g. profiler becoming default-on) is MAJOR; detection-rule additions are MINOR (they can
      change runtime behavior); pure fixes are PATCH.

---

## 🌐 Stage 2 — OWASP Incubator Submission

**Focus:** Community readiness and project governance.

### Before submitting

- [ ] **Community baseline:** `CODE_OF_CONDUCT.md`, issue/PR templates, `GOVERNANCE.md`, and a
      `good-first-issue` backlog. Taint-propagation targets (each additional `string` method to
      instrument) are ideal starter issues — small, well-scoped, with an existing pattern to copy.
- [ ] **Isolate the intentionally-vulnerable demo target** (`modules/`) so its known-vulnerable
      packages are never mistaken for product dependencies — clear labeling, separate solution
      filter, and exclusion from any dependency-scanning badge the product advertises.
- [ ] **Recruit a second project leader.** Current OWASP policy requires multiple leaders (not
      all from the same employer), and all leaders need admin on the repository — this gates the
      application itself, it is not a post-acceptance nicety. An engaged external contributor
      (someone who has already read the code deeply enough to open a real issue) is the natural
      first candidate.
- [ ] **Start the [OSSF Best Practices](https://www.bestpractices.dev/) self-certification.**
      A Lab-promotion criterion that costs little to begin early — it is a questionnaire, and
      most of the answers (license, tests, SECURITY.md, release discipline) already exist.
- [ ] **Draft the OWASP project-page content** (`index.md`, description, roadmap) in advance.
      The `www-project-rasp-net` repository is provisioned by the OWASP Foundation under
      `github.com/OWASP` only **after** acceptance — you cannot create it yourself. Having the
      content ready means the page goes live the day the repo is provisioned instead of weeks
      later.
- [ ] **Submit as an [OWASP Incubator project](https://owasp.org/projects/).** The entry bar —
      open source, vendor-neutral, security-focused — is already met: MIT license,
      [threat model](ATTACK_SCENARIOS.md), [SECURITY.md](../SECURITY.md), no corporate steering.
      Submission goes through the official OWASP project application; review turnaround is
      typically 4–8 weeks.

### After acceptance

- [ ] **Transfer the repository to `github.com/OWASP`** (required by OWASP project policy —
      private accounts are not permitted). GitHub preserves stars, issues and history and
      redirects old URLs; what needs manual care: re-creating Actions secrets (e.g. the release
      signing key), the Codecov integration, and badge URLs. The demo-target submodule can stay
      on a personal account — it is test tooling, not the product.
- [ ] **Populate `www-project-rasp-net`** with the drafted content and keep it current with
      releases and roadmap — stale project pages are what gets OWASP projects flagged inactive.

---

## 🛡️ Stage 3 — [OWASP Top 10 (2025)](https://owasp.org/Top10/2025/) Coverage

**Focus:** The main feature track once the product is installable — closing the ⬜ rows below is
what drives Incubator → Lab progression.

A sink-based RASP is a natural fit for the injection/integrity/exception-handling families and a
poor fit for categories that are really about access-control policy, cryptography, or supply
chain — the mapping is kept honest rather than padded. Note the 2025 edition folded SSRF
(CWE-918) into **A01 Broken Access Control** rather than keeping it a standalone category, and
added **A10 Mishandling of Exceptional Conditions**, a much more precise fit for the deferred
Lean Sentinel work than the 2021 edition's A04/A09 had been.

| Category | Coverage | Mechanism |
|:---|:---|:---|
| **A01 Broken Access Control** (SSRF — CWE-918, Path Traversal) | ✅ Done | `SsrfGuard` (DNS-rebinding-safe `HttpClient` handler, [ADR 006](ADR/006-sink-instrumentation-strategy.md)), `PathTraversalGuard` (MonoMod). The rest of A01 — IDOR, JWT/session handling, CORS — is access-control *policy*, not a sink a RASP can validate. |
| **A02 Security Misconfiguration** (headers) | ✅ Done | `RaspSecurityHeadersMiddleware` (CSP, etc.) |
| **A02 / A05 XXE** (`XmlReader` / `XmlDocument.Load`) | ⬜ Planned | policy guard disabling DTD/external entities (MonoMod) |
| **A05 Injection** (SQLi, XSS, Command Injection) | ✅ Done | `SqlSinkGuard`, source-generated XSS/SQLi scan, `CommandInjectionGuard` (MonoMod) |
| **A05 Injection** (LDAP Injection — `DirectorySearcher`) | ⬜ Planned | new `LdapInjectionDetectionEngine` (MonoMod) |
| **A08 Software or Data Integrity Failures** (insecure deserialization) | ✅ Done | `DeserializationGuard` + `System.Text.Json` type-info modifier |
| **A09 Security Logging & Alerting Failures** | ✅ Done | `RaspAlertBus`, correlated structured alerts ([ADR 007](ADR/007-execution-context.md)), audit mode, metrics |
| **A10 Mishandling of Exceptional Conditions** (error messages/stack traces leaking system detail) | ⬜ Deferred | Lean Sentinel ([ADR 004](ADR/004-memory-disclosure-protection.md) — accepted, implementation deferred) |
| A03 (Software Supply Chain), A04 (Cryptographic Failures), A06 (Insecure Design), A07 (Authentication Failures) | Out of scope | Dependency/CI-CD integrity, cryptography, architecture-level design review, and authentication are a different tooling category than a sink-based RASP; deliberately not attempted here. |

### Planned-item detail

- **XXE policy guard:** MonoMod patch on `XmlReader.Create` / `XmlDocument.Load` enforcing
  DTD-off / no-external-entities defaults, with the same block-or-audit policy shape as the
  existing guards.
- **LDAP injection:** a new span-based `LdapInjectionDetectionEngine` wired to
  `DirectorySearcher` / `DirectoryEntry` sinks via MonoMod — same `IDetectionEngine` contract as
  the SQL/XSS engines, so it plugs into the existing alert and context plumbing unchanged.
- **Lean Sentinel ([ADR 004](ADR/004-memory-disclosure-protection.md), accepted — implementation
  deferred):** deterministic memory-disclosure protection without statistical analysis —
  **response size hard caps**, **SIMD binary pattern scanning** for immutable secrets
  (`sk_live_`, `xoxb-`) in outbound traffic, and **debug artifact detection**
  (`0xCDCD` / `0xABAB` heap patterns in production). Under the 2025 Top 10 this maps cleanly to
  A10 rather than being spread across the 2021 edition's A04/A09.

---

## 🔭 Stage 4 — Depth, Platform Reach, Foundation

**Focus:** Taint depth, Linux parity, long-term governance.

- [ ] **Widen taint propagation** beyond `String.Concat(string, string)`: `string.Format`,
      string-interpolation lowering, `Substring`, `StringBuilder` — the gap
      [ADR 006](ADR/006-sink-instrumentation-strategy.md) documents as v1's accepted limitation.
      Each new propagation target is an isolated, testable IL-rewrite case (and a candidate
      `good-first-issue` from Stage 2).
- [ ] **Native test harness + Linux profiler port.** The IL rewriter currently has only a smoke
      test; profiler bugs corrupt JIT/runtime state rather than throwing catchable exceptions, so
      a real native test harness precedes any port. The profiler build is Windows-only today, but
      the non-Windows PAL scaffolding already exists (`profiler_pal.h`). Linux is where most
      ASP.NET Core production runs — this is what removes the "Windows-only advanced preview"
      label from Phase C.
- [ ] **Linux native integrity parity — eBPF ([ADR 003](ADR/003-native-integrity-guard.md)):**
      inject verified BPF programs to monitor `ptrace` and other syscalls used by debuggers and
      dumpers, matching the Windows C++ guard's capabilities in Kubernetes/Docker environments.
    - *Stealth:* monitoring happens in kernel space, invisible to user-mode attackers.
    - *Performance:* event-driven detection, zero context-switching penalty for the .NET app.
    - *Container awareness:* detect container-escape attempts and namespace manipulation.
- [ ] **.NET Foundation application (cost-benefit decision, not a default).** Only once packages
      are published, adoption signals exist, and the maintainer bus factor is above one — the
      Foundation works as a maturity seal, not a launch lever. Being an OWASP project does not
      structurally conflict: OWASP mandates repo *location* (`github.com/OWASP`), while the
      Foundation's current criteria only require publicly accessible code. Its one concrete perk
      for this project is code-signing assistance (the open Authenticode decision in
      [ADR 006](ADR/006-sink-instrumentation-strategy.md) addendum point 5); if SignPath has
      already covered that by then, membership is mostly ceremonial and may not pay for its
      overhead (second code of conduct, second annual review, third-party bots on an OWASP-owned
      org).

---

## 📊 Feature Matrix

| Capability | Today | Stage 1–2 (Product & Community) | Stage 3 (Coverage) | Stage 4 (Depth & Platform) |
| :--- | :--- | :--- | :--- | :--- |
| **Detection Engines** | ✅ SQLi + XSS (SIMD / Span, zero-alloc) | — | + LDAP engine, XXE policy guard | — |
| **Perimeter Integration** | ✅ Source Generators (dynamic descriptor fallback) | — | — | — |
| **Sink Guards** | ✅ SQL · SSRF · Path Traversal · Command Injection · Deserialization | packaged (core vs. opt-in MonoMod) | + XXE, LDAP | — |
| **Taint Tracking** | ✅ v1 — `String.Concat(string, string)`, Windows-only | ships as advanced preview | — | widened propagation, Linux port |
| **Source → Sink Correlation** | ✅ `RaspContext` (ADR 007) | — | — | — |
| **Memory Guard (Lean Sentinel)** | ⬜ Accepted, deferred (ADR 004) | — | **implemented (A10)** | — |
| **Windows Native Security** | ✅ Native C++ guard | — | — | — |
| **Linux Native Security** | ⚠️ Managed `Debugger.IsAttached` only | — | — | **eBPF kernel hooks** 🐧 |
| **Packaging** | ❌ Source-only, `net10.0` | **NuGet, `net8.0;net10.0`, signed SemVer** 📦 | — | — |
| **Governance** | MIT, threat model, SECURITY.md | **OWASP Incubator** 🌐 | Incubator → Lab | **.NET Foundation** |
