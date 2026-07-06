# Good First Issues: .NET-only (no native profiler)

Companion to [good-first-issues.md](good-first-issues.md), which is all C++/IL-rewrite work.
Everything here is C#, targets Stage 3 of [ROADMAP.md](ROADMAP.md) — closing the remaining
OWASP Top 10 rows and the AI/LLM boundary from [ADR 011](ADR/011-ai-llm-boundary.md) — and
needs no `Rasp.Native.Profiler` knowledge. Same expectation as the other backlog: a unit
test per PR, and a BenchmarkDotNet number in the PR description per
[CONTRIBUTING.md](../CONTRIBUTING.md) for anything touching a guard or engine.

Each issue below has a "Ready-to-file issue" block: copy everything inside the fence as the
GitHub issue description (the first line is the suggested title).

---

## LDAP Injection (Stage 3, A05 — ⬜ Planned)

### Not seeded as good-first-issue: `LdapInjectionDetectionEngine`

Filing the engine itself as a starter issue was a mistake in an earlier pass of this
document — flagged correctly: unlike copying `Concat`'s IL-rewrite shape or copying
`SqlSinkGuardTaintTests.cs`'s test shape, there's no existing, already-validated answer to
copy here. Someone has to *decide* the LDAP DN/filter bailout set and curate a
signature list for filter-injection shapes (`)(uid=*`, `)(|`, wildcard-anywhere-in-filter)
that's accurate enough not to false-positive on legitimate filters — a real security-design
judgment call in a product that ships block-by-default, not a mechanical port of a known
pattern. File this as a normal feature issue (`help wanted`, not `good-first-issue`), same
category as the LLM-boundary phases above.

<details>
<summary>Ready-to-file issue (help wanted, not good-first-issue)</summary>

```markdown
Title: New detection engine: `LdapInjectionDetectionEngine` (A05, LDAP injection)

## Summary
Design and implement a new `IDetectionEngine` for LDAP filter/DN injection, following the
span-based, SIMD-bailout shape of the existing engines.

## Background
[ROADMAP.md](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ROADMAP.md) Stage 3
lists LDAP Injection (A05) as ⬜ Planned. This is **not** a mechanical port of an existing
pattern — it requires deciding the actual detection heuristics (which characters/shapes
indicate a filter-injection attempt vs. a legitimate `DirectorySearcher` filter), so it
should not be labeled `good-first-issue`. It's a reasonable issue for a contributor who
wants to go deeper, or for the maintainer.

## What's needed
- A `LdapInjectionDetectionEngine : IDetectionEngine` in `src/Rasp.Core/Engine/`, following
  the shape of `XssDetectionEngine` (`src/Rasp.Core/Engine/XssDetectionEngine.cs`): a
  `SearchValues<char>` bailout set for LDAP DN/filter metacharacters (candidates: `* ( ) \
  NUL /`), then a signature list for known filter-injection shapes (e.g. `)(uid=*`, `)(|`,
  a wildcard appearing where it shouldn't).
- Explicit test cases distinguishing legitimate filters (containing metacharacters as part
  of a normal, non-injected query) from actual injection attempts — the false-positive rate
  is the real design risk here, and needs its own discussion/review, not just a green test
  suite.
- Implements both `Inspect` overloads on `IDetectionEngine`
  (`src/Rasp.Core/Abstractions/IDetectionEngine.cs`).

## Acceptance criteria
- [ ] Engine implemented, unit-tested with both attack and legitimate-filter cases.
- [ ] BenchmarkDotNet number in the PR description (per `CONTRIBUTING.md`) — clean-input
      path should stay in the zero-allocation, sub-microsecond range like the SQL/XSS
      engines.
- [ ] Detection heuristics and their rationale documented in the PR description or a short
      ADR addendum, since this is a judgment call future maintainers will need to revisit.
- [ ] Does **not** need to include the `DirectorySearcher`/`DirectoryEntry` MonoMod wiring —
      that's a separate, genuinely good-first-issue-sized follow-up (see the companion
      issue in `docs/good-first-issues-dotnet.md`).

## Labels
`help wanted`, `detection-engine`, `owasp-top-10`
```

</details>

### 2. `LdapSinkGuard` + MonoMod patch on `DirectorySearcher` / `DirectoryEntry`

This part is genuinely good-first-issue-sized, but only once the engine above exists to
wire up to. Copy `CommandInjectionGuard` (`src/Rasp.Core/Guard/CommandInjectionGuard.cs`,
engine + alert bus + metrics + block-or-audit) for the guard, and `ProcessStartPatch`
(`src/Rasp.Instrumentation.RuntimePatching/Patches/ProcessStartPatch.cs`) for the `ILHook`
shape — same `ReentrancyGuard`-wrapped delegate pattern, hooking `DirectorySearcher.FindOne`
/ `FindAll` instead of `Process.Start`. No detection-logic judgment involved, purely wiring.

<details>
<summary>Ready-to-file issue (blocked on the engine issue above)</summary>

```markdown
Title: `LdapSinkGuard` + MonoMod patch on `DirectorySearcher`/`DirectoryEntry`

## Summary
Wire the (already-merged) `LdapInjectionDetectionEngine` to a real sink: a guard plus a
MonoMod `ILHook` on `DirectorySearcher.FindOne`/`FindAll`. Pure wiring, copying two
existing patterns exactly — no new detection logic.

## Background
Blocked on `LdapInjectionDetectionEngine` existing (see the companion "help wanted" issue).
Once that engine is merged, this issue is a mechanical copy of two existing files.

## What changes
- New `LdapSinkGuard` in `src/Rasp.Core/Guard/`, copying the shape of
  `CommandInjectionGuard` (`src/Rasp.Core/Guard/CommandInjectionGuard.cs`): constructor
  takes the engine + `RaspAlertBus` + `IRaspMetrics` + `IOptions<RaspOptions>` + `ILogger`;
  an `AnalyzeFilter(string filter, string context)` method that inspects, records metrics,
  and blocks-or-audits per `RaspOptions` (add a new `BlockOnLdapInjectionDetection` option
  or reuse an existing block flag — decide which in the PR).
- New patch in `src/Rasp.Instrumentation.RuntimePatching/Patches/`, copying the shape of
  `ProcessStartPatch.cs`: an `ILHook` on `DirectorySearcher.FindOne`/`FindAll` (and
  `DirectoryEntry` where relevant) that extracts the filter string and calls
  `LdapSinkGuard.AnalyzeFilter`, wrapped in `ReentrancyGuard.Enter()` like the existing
  patches.

## Acceptance criteria
- [ ] Guard blocks or audits per configured `RaspOptions`, matching the shape of every
      other guard (alert pushed via `RaspAlertBus`, `RaspSecurityException` thrown when
      blocking).
- [ ] MonoMod patch correctly extracts the filter string from `DirectorySearcher`.
- [ ] Unit test for the guard (mirroring the pattern in the guard-unit-test issues below).
- [ ] BenchmarkDotNet number in the PR description.

## Labels
`good-first-issue`, `owasp-top-10`, `difficulty:medium`
```

</details>

---

## XXE Policy Guard (Stage 3, A02/A05 — ⬜ Planned)

### 3. Harden `XmlReader.Create` / `XmlDocument.Load` defaults via MonoMod

Not a signature-based engine — this is a policy guard (DTD processing off,
`XmlResolver = null` for external entities) enforced at the same choke point pattern as
`FileStreamPatch` (`src/Rasp.Instrumentation.RuntimePatching/Patches/FileStreamPatch.cs`).
Block-or-audit shape matches every other guard. No new `IDetectionEngine` needed, so this
is more mechanical than the LDAP guard, but it's still a MonoMod `ILHook`, so file it after
someone has shipped at least one guard from the taint-propagation or LDAP list — good second
or third issue, not literally first.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: XXE policy guard: harden `XmlReader.Create`/`XmlDocument.Load` defaults via MonoMod

## Summary
Enforce safe XML parsing defaults (DTD processing off, external entity resolution
disabled) at the point `XmlReader.Create`/`XmlDocument.Load` is called, via a MonoMod
`ILHook`, matching the shape of the existing runtime patches.

## Background
[ROADMAP.md](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ROADMAP.md) Stage 3
lists XXE (A02/A05) as ⬜ Planned. Unlike the LDAP engine, this is not a signature-matching
detection problem — it's enforcing the well-known, single canonical mitigation (DTD off,
`XmlResolver = null`), so no new `IDetectionEngine` is needed.

## What changes
- New patch in `src/Rasp.Instrumentation.RuntimePatching/Patches/`, following the shape of
  `FileStreamPatch.cs` (`src/Rasp.Instrumentation.RuntimePatching/Patches/FileStreamPatch.cs`):
  an `ILHook` on `XmlReader.Create` (all relevant overloads) and `XmlDocument.Load` that
  enforces `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit` and
  `XmlResolver = null` unless the caller has explicitly opted out via `RaspOptions`.
- Same block-or-audit policy shape as every other guard — if the caller supplied settings
  that already re-enable DTD/external entities, either overwrite them (block posture) or
  alert-and-allow (audit posture) depending on configuration.

## Acceptance criteria
- [ ] `XmlReader.Create`/`XmlDocument.Load` calls get hardened settings by default.
- [ ] Block-or-audit behavior configurable via `RaspOptions`, matching existing guards.
- [ ] Unit test confirming a DTD-bearing/external-entity payload is rejected (or audited)
      as configured.
- [ ] BenchmarkDotNet number in the PR description.

## Labels
`good-first-issue`, `owasp-top-10`, `difficulty:medium`
```

</details>

---

## Lean Sentinel (ADR 004, accepted — deferred implementation, A10)

Three independent components, all pure `ReadOnlySpan<byte>`/`char` work in the gRPC
response path, none touching MonoMod or the native profiler. [ADR 004](ADR/004-memory-disclosure-protection.md)
already rejected the harder approaches (canary poisoning, entropy, Z-score) — the spec below
is deliberately the boring, deterministic version that's left.

### 4. Response size hard caps

Per-endpoint max response size, enforced in the gRPC interceptor layer; block responses
that exceed the configured cap. No detection engine, no span scanning — a size check and
the existing block-or-audit/alert-bus plumbing. The easiest of the four Lean Sentinel
issues.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Lean Sentinel: per-endpoint response size hard caps

## Summary
Enforce an explicit, per-endpoint maximum response size in the gRPC interceptor layer;
block responses that exceed the configured cap. Detects mass memory-disclosure scenarios
(Heartbleed-style over-reads).

## Background
[ADR 004](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/004-memory-disclosure-protection.md)
("Lean Sentinel") is accepted but not yet implemented. This is component 1 of 3 (Core
Component 1, "Response Size Hard Limits") and the simplest — no detection engine, no span
scanning, just a size check.

## What changes
- A response-size check in the gRPC interceptor layer (wherever outbound messages are
  serialized before being written to the response stream), comparing against a configured
  per-endpoint (or global default) maximum.
- Same block-or-audit shape as every other guard: alert via `RaspAlertBus`, block by
  throwing/rejecting when over the cap and blocking is enabled, audit-only otherwise.
- Configuration surface on `RaspOptions` for the cap(s).

## Acceptance criteria
- [ ] A response exceeding the configured cap is blocked (or audited) as configured.
- [ ] A response under the cap is unaffected.
- [ ] Unit test covering both paths.
- [ ] BenchmarkDotNet number confirming near-zero overhead on the common case (response
      under the cap) — ADR 004 targets < 100ns overhead.

## Labels
`good-first-issue`, `owasp-top-10`, `difficulty:easy`
```

</details>

### 5. SIMD secret-prefix scanner for outbound responses

`SearchValues<byte>` scan for a short, fixed list of immutable secret prefixes (`sk_live_`,
`xoxb-`) in outbound response bytes — same bailout-then-signature-match shape as
`XssDetectionEngine`, but over `ReadOnlySpan<byte>` instead of `char`, and no canonicalization
step (ADR 004 explicitly rejects generic token/entropy detection, so there's no decode pass
to write). Confidentially: **this scanner is the one ADR 011 Phase 2's system-prompt canary
is meant to share** — worth reading that ADR's Phase 2 section before naming things, so the
two don't duplicate a `SearchValues`-based exact-match implementation.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Lean Sentinel: SIMD secret-prefix scanner for outbound responses

## Summary
Scan outbound gRPC response bytes for a short, fixed list of immutable secret prefixes
(e.g. `sk_live_`, `xoxb-`) using `SearchValues<byte>`. Deterministic, no generic
token/entropy detection.

## Background
[ADR 004](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/004-memory-disclosure-protection.md)
("Lean Sentinel") Core Component 2, "High-Fidelity Pattern Scanning" — deliberately narrow:
only explicitly forbidden, immutable prefixes, never generic entropy/token inference (that
approach was evaluated and rejected in the ADR).

**Naming note:** this scanner is meant to be shared with [ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
Phase 2's system-prompt canary check (also a `SearchValues` exact-match scan). Check whether
that issue has already landed or is in progress before duplicating the implementation —
coordinate on one shared scanner if so.

## What changes
- A new scanner (in `src/Rasp.Core/` — engine or guard, matching whichever wiring point
  makes sense for the gRPC response path) using `SearchValues<byte>` for a bailout scan over
  the response bytes, matching against a fixed, documented list of secret prefixes.
- Same shape as `XssDetectionEngine`'s bailout-then-signature approach
  (`src/Rasp.Core/Engine/XssDetectionEngine.cs`), but on `ReadOnlySpan<byte>` — no
  canonicalization/decode pass, since ADR 004 explicitly rejects generic detection.
- Immediate alert on match; this is a fixed-signature match, not a probabilistic signal.

## Acceptance criteria
- [ ] A response containing a listed secret prefix triggers an alert (block-or-audit per
      configuration).
- [ ] A clean response incurs no false positive and stays on the zero-allocation fast path.
- [ ] Unit test covering both cases.
- [ ] BenchmarkDotNet number — ADR 004 targets < 100ns overhead, zero allocations.
- [ ] PR description notes the potential shared-implementation overlap with ADR 011 Phase 2's
      canary scan.

## Labels
`good-first-issue`, `owasp-top-10`, `difficulty:medium`
```

</details>

### 6. Debug heap-pattern scanner (`0xCDCD` / `0xABAB`)

Binary scan for well-known uninitialized/freed-memory patterns in outbound response bytes.
Same shape as #5 (fixed byte signatures, `SearchValues<byte>`), immediate high-severity
alert on any match — this pattern in a production response means a build or memory-pooling
bug, not an ambiguous signal, so there's no block-or-audit choice to design, only alerting.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Lean Sentinel: debug heap-pattern scanner (`0xCDCD`/`0xABAB`)

## Summary
Scan outbound response bytes for well-known debug-heap patterns (`0xCDCD`, `0xABAB`) that
indicate uninitialized or freed memory leaking into a response. Immediate high-severity
alert on any match — there is no legitimate reason for these bytes to appear in production
output.

## Background
[ADR 004](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/004-memory-disclosure-protection.md)
("Lean Sentinel") Core Component 3, "Debug Artifact Detection". Presence of these patterns
in a production response indicates a build or memory-management flaw, not an ambiguous
security signal — so unlike the other guards, there's no block-vs-audit policy decision to
design here, only alerting (though blocking on match is reasonable to also support).

## What changes
- A scanner alongside the secret-prefix scanner (issue: SIMD secret-prefix scanner), same
  `SearchValues<byte>` shape, matching the fixed `0xCDCD`/`0xABAB` byte patterns (and any
  other well-known debug-heap markers worth including — document the choice).
- Immediate high-severity alert via `RaspAlertBus` on any match.

## Acceptance criteria
- [ ] A response containing one of the listed patterns triggers a high-severity alert.
- [ ] A clean response incurs no false positive and stays on the zero-allocation fast path.
- [ ] Unit test covering both cases.
- [ ] BenchmarkDotNet number — ADR 004 targets < 100ns overhead, zero allocations.

## Labels
`good-first-issue`, `owasp-top-10`, `difficulty:medium`
```

</details>

---

## The AI/LLM boundary (ADR 011, Stage 3 second half)

Gate from the ADR itself, respect it: **Phase 3 issues must not merge before Phase 1 and
Phase 2 are shipped and benchmarked.** They can be coded and reviewed in parallel, but the
ADR's own mitigations section treats phase order as a hard rule, not a suggestion — say so
in the PR if picking up a Phase 3 item early.

### 7. Scaffold `Rasp.Instrumentation.Ai` + `DelegatingChatClient` taint-source wrapper (Phase 1)

The package doesn't exist yet — first PR here also creates the project, following the
naming/layout of the existing `Rasp.Instrumentation.*` projects (e.g.
`src/Rasp.Instrumentation.HttpClient`). The wrapper itself: a `DelegatingChatClient`
(`Microsoft.Extensions.AI`) that calls `RaspTaintSensor.MarkTainted` on every text segment
of a model response and stamps the current `RaspContext` (or synthesizes an orphan one per
[ADR 007](ADR/007-execution-context.md)) — no new taint machinery, this only calls existing
`Rasp.Core` APIs. Covers LLM05.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: `Rasp.Instrumentation.Ai`: scaffold package + `DelegatingChatClient` taint-source wrapper (ADR 011 Phase 1)

## Summary
Create the `Rasp.Instrumentation.Ai` package and implement a `DelegatingChatClient` wrapper
that marks every text segment of a model response as tainted and stamps the current
`RaspContext` — the LLM-output-as-taint-source half of ADR 011 Phase 1.

## Background
[ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
proposes treating LLM output as an untrusted taint source. Phase 1 is the deterministic
first step: mark model output tainted using the *existing* `RaspTaintSensor` — no new taint
machinery. Covers OWASP LLM Top 10's LLM05 (Improper Output Handling).

## What changes
- New project `src/Rasp.Instrumentation.Ai`, following the layout/naming of existing
  `Rasp.Instrumentation.*` projects (e.g. `src/Rasp.Instrumentation.HttpClient`).
- A `DelegatingChatClient`-derived wrapper (`Microsoft.Extensions.AI`) that, on every model
  response: calls `RaspTaintSensor.MarkTainted(...)` (`src/Rasp.Core/Context/RaspTaintSensor.cs`)
  on each text segment, and stamps the current `RaspContext` — reusing
  `RaspExecutionContext.Current`, or synthesizing an orphan context per the pattern already
  used in the existing guards (see e.g. `src/Rasp.Core/Guard/CommandInjectionGuard.cs`), per
  [ADR 007](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/007-execution-context.md).
- No changes needed to any sink guard — they already inspect content unconditionally.

## Acceptance criteria
- [ ] `Rasp.Instrumentation.Ai` project created, multi-targeted consistent with the rest of
      the solution.
- [ ] Wrapping an `IChatClient` and receiving a response marks the response text tainted
      (verifiable via `RaspTaintSensor.IsTainted`).
- [ ] `RaspContext` correlation is present on the marked response (or an orphan context is
      synthesized when none is ambient).
- [ ] Unit test(s) covering the wrapper.
- [ ] Does not touch the hot path for services that don't reference this package (per ADR
      011's "performance posture" — this package should cost nothing when unused).

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:medium`
```

</details>

### 8. Fake `IChatClient` endpoint + `attack/exploit_llm.py` (Phase 1 validation)

Add one endpoint to the victim app (`modules/dotnet-grpc-library-api`) backed by a
deterministic fake `IChatClient` — scripted responses, no live model, no network — per
[ADR 001](ADR/001-composite-architecture.md)'s validation pattern. Then a red-team script
mirroring the existing `attack/exploit_xss.py` / `exploit_sqli.py` shape that drives a
poisoned "model output" through to a sink in CI. Can be built in parallel with #7 against a
stub client; needed before #7 can be called done, not before it can be started.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Fake `IChatClient` victim-app endpoint + `attack/exploit_llm.py` (ADR 011 Phase 1 validation)

## Summary
Add one endpoint to the victim app backed by a deterministic fake `IChatClient` (scripted
responses, no live model, no network), plus a red-team script that drives a poisoned "model
output" through to a sink in CI — the validation harness for ADR 011 Phase 1.

## Background
[ADR 001](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/001-composite-architecture.md)'s
composite-architecture pattern validates every guard against the real victim app
(`modules/dotnet-grpc-library-api`). [ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
needs the same treatment for the LLM boundary, but the victim app has no LLM surface today
and must not make live model calls (CI needs to be deterministic, not flaky).

## What changes
- One new endpoint in `modules/dotnet-grpc-library-api` backed by a fake `IChatClient`
  implementation returning scripted responses — no real model, no network call.
- `attack/exploit_llm.py`, mirroring the shape of the existing `attack/exploit_xss.py` /
  `attack/exploit_sqli.py` scripts: drives a poisoned "model output" scripted response
  through to a guarded sink (e.g. SQL, command) and asserts the guard fires.

## Acceptance criteria
- [ ] New victim-app endpoint compiles and runs with zero external network dependencies.
- [ ] `attack/exploit_llm.py` runs in CI alongside the existing exploit scripts and
      exercises at least one poisoned-output → sink chain.
- [ ] Can be developed and merged independently of issue #7 (the `DelegatingChatClient`
      wrapper) using a stub client, though the full validation story needs both.

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:medium`
```

</details>

### 9. Tool-call allowlist/denylist guard (Phase 2)

A policy guard that runs before an `IChatClient` function call (or Semantic Kernel's
`IFunctionInvocationFilter`) executes: block or audit calls to functions not on an
operator-configured list, per `RaspOptions`. Same shape as every other guard in this repo —
no new detection engine, a policy check plus the existing alert-bus/metrics plumbing.
Covers LLM06, ASI02, ASI03. Depends on #7 existing (needs the package skeleton), not on it
being finished.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Tool-call allowlist/denylist guard (ADR 011 Phase 2)

## Summary
A policy guard that runs before an agent's tool/function call executes, blocking or
auditing calls to functions not on an operator-configured allowlist. Covers OWASP LLM06
(Excessive Agency) and Agentic Top 10's ASI02/ASI03.

## Background
[ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
Phase 2 is the deterministic enforcement point for agentic tool use: an agent hijacked into
calling a function the operator never listed should be stopped regardless of how the hijack
was phrased. Needs the `Rasp.Instrumentation.Ai` package skeleton (see the scaffolding
issue) to exist, but not to be finished.

## What changes
- A new guard in `Rasp.Instrumentation.Ai` hooking `IChatClient` function calling (and/or
  Semantic Kernel's `IFunctionInvocationFilter`), checking the invoked function name against
  an operator-configured allowlist/denylist in `RaspOptions`.
- Same block-or-audit shape as every existing guard (see e.g.
  `src/Rasp.Core/Guard/CommandInjectionGuard.cs`): alert via `RaspAlertBus`, block by
  throwing when configured to.

## Acceptance criteria
- [ ] A call to a disallowed function is blocked (or audited) per configuration.
- [ ] A call to an allowed function proceeds unaffected.
- [ ] Unit test covering both paths.
- [ ] BenchmarkDotNet number in the PR description if this sits anywhere near a hot path;
      otherwise note in the PR why it doesn't (per ADR 011's performance posture, an LLM
      round trip already costs hundreds of ms, so this check is expected to be noise).

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:medium`
```

</details>

### 10. Tool-argument inspection through existing engines (Phase 2)

Once #9's guard runs before a tool call, route the tool's string arguments through the
existing `IDetectionEngine` set (SQLi/XSS/command/path — whichever the argument shape
suggests) before the tool body executes, the same way an inbound gRPC field is scanned
today. No new engines: this issue is entirely about wiring, not detection logic.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Tool-argument inspection through existing detection engines (ADR 011 Phase 2)

## Summary
Route an agent tool call's string arguments through the existing `IDetectionEngine` set
(SQLi/XSS/command/path) before the tool body executes — the same treatment an inbound gRPC
field already gets. No new detection logic, pure wiring.

## Background
[ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
Phase 2: a tool argument is a string a hostile model output can shape, so it should get the
same scan an inbound field gets, in addition to (not instead of) the sink guard that fires
inside the tool body — defense in depth, both layers already exist independently.

## What changes
- In the tool-call guard added by issue #9 (or alongside it), before invoking the tool
  body: pass each string argument through the relevant existing `IDetectionEngine`
  implementation(s) (`src/Rasp.Core/Engine/`), the same way the source-generated gRPC
  interceptor scans inbound fields today.
- Alert via the existing `RaspAlertBus` plumbing on a match; this is an additional signal
  layered on top of the allowlist/denylist check and the sink guard, not a replacement for
  either.

## Acceptance criteria
- [ ] A tool call with a malicious-shaped argument (matching an existing engine's
      signature) is flagged before the tool body executes.
- [ ] A tool call with clean arguments proceeds unaffected.
- [ ] Unit test covering at least one engine (e.g. SQLi) wired through this path.

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:easy`
```

</details>

### 11. System-prompt canary scanner (Phase 2)

Exact-match `SearchValues` scan of chat responses for an operator-configured marker string
embedded in the system prompt. **Read issue #5 first** — this is explicitly meant to reuse
Lean Sentinel's SIMD exact-match mechanism rather than reimplement it; if #5 hasn't landed
yet, coordinate rather than duplicating. Covers LLM07.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: System-prompt canary scanner (ADR 011 Phase 2)

## Summary
Detect system-prompt leakage by scanning chat responses for an operator-configured marker
string embedded in the system prompt, via an exact-match `SearchValues` scan. Covers OWASP
LLM07 (System Prompt Leakage).

## Background
[ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
Phase 2. **This is explicitly meant to share its scanning mechanism with the Lean Sentinel
secret-prefix scanner** (see that issue in this same document) — both are fixed-string,
`SearchValues`-based exact-match scans. Check whether that issue has landed or is in
progress before implementing a second, separate scanner.

## What changes
- A scan of chat response text for an operator-configured canary string (embedded by the
  operator into the system prompt), using the same `SearchValues`-based exact-match
  mechanism as the Lean Sentinel secret-prefix scanner — share the implementation if that
  issue has already merged, or coordinate to build both against one shared scanner if not.
- Alert (block or audit per `RaspOptions`) on any match.

## Acceptance criteria
- [ ] A response containing the configured canary string is flagged.
- [ ] A clean response incurs no false positive.
- [ ] Unit test covering both cases.
- [ ] PR description confirms whether this reused or duplicated the Lean Sentinel scanner,
      and why.

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:medium`
```

</details>

### 12. `IPromptClassifier` seam (Phase 3 — do not merge before #7–#11 ship)

Smallest possible Phase 3 issue and a reasonable one to hand to a first-time contributor
once the phase gate clears: define the interface (async, out-of-band, takes prompt text,
returns a classification result) plus a no-op default implementation. No detection logic —
this is a seam for operators to wire Azure Prompt Shields / LLM Guard / a self-hosted model
themselves. Ships audit-mode only, documented as outside the latency budget and outside this
project's accuracy claims.

<details>
<summary>Ready-to-file issue — do not merge before issues #7–#11 ship</summary>

```markdown
Title: `IPromptClassifier` seam (ADR 011 Phase 3)

## Summary
Define an `IPromptClassifier` interface (async, out-of-band) and a no-op default
implementation, giving operators a seam to wire an external prompt classifier (Azure Prompt
Shields, LLM Guard, a self-hosted model) without this project taking on classification
itself.

## Background
[ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
Phase 3. **Gate: per the ADR's own mitigations section, no Phase 3 work should merge before
Phase 1 and Phase 2 (issues #7–#11 in this backlog) are shipped and benchmarked.** This
issue can be coded/reviewed early but should not merge ahead of that gate.

## What changes
- `IPromptClassifier` interface in `Rasp.Instrumentation.Ai`: async method taking prompt
  text, returning a classification result type (define the result shape — at minimum a
  confidence/verdict signal, documented as an indicator, not a verdict).
- A no-op default implementation (always returns "no signal") so the seam is safe by
  default with nothing wired.
- Documentation stating plainly that this seam is outside the latency budget and outside
  this project's own accuracy claims — matching the honesty posture the ADR asks for.

## Acceptance criteria
- [ ] Interface and no-op implementation added, with XML doc comments explaining the
      contract and its limitations.
- [ ] Does not merge before issues #7–#11 (Phase 1/2) have shipped and been benchmarked —
      confirm this in the PR description.
- [ ] Ships audit-mode only; no default wiring that could block traffic based on an
      unconfigured classifier.

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:easy`, `blocked-on-phase-gate`
```

</details>

### 13. Invisible-Unicode "Tags block" detector (Phase 3 — do not merge before #7–#11 ship)

Span-based scanner for the Unicode Tags block (`U+E0000`–`U+E007F`) and zero-width joiners
used for instruction smuggling in inbound text. Audit-mode only, per ADR 011 — this is an
indicator, not a verdict. Same `SearchValues`/span-scan shape as every other engine in this
codebase, applied to a code-point range instead of a fixed string list.

<details>
<summary>Ready-to-file issue — do not merge before issues #7–#11 ship</summary>

```markdown
Title: Invisible-Unicode "Tags block" detector (ADR 011 Phase 3)

## Summary
A span-based scanner for the Unicode Tags block (`U+E0000`–`U+E007F`) and zero-width
joiners in inbound text — indicators of instruction-smuggling techniques used in some
prompt-injection attacks. Audit-mode only; an indicator, not a verdict.

## Background
[ADR 011](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/011-ai-llm-boundary.md)
Phase 3. **Gate: per the ADR's own mitigations section, no Phase 3 work should merge before
Phase 1 and Phase 2 (issues #7–#11 in this backlog) are shipped and benchmarked.** This
issue can be coded/reviewed early but should not merge ahead of that gate.

## What changes
- A scanner over inbound text (wherever text destined for a model prompt is captured) for
  code points in the Unicode Tags block range and known zero-width-joiner smuggling
  patterns, using the same `SearchValues`/span-scan shape as the existing detection engines
  (e.g. `src/Rasp.Core/Engine/XssDetectionEngine.cs`), applied to a code-point range instead
  of a fixed string list.
- Audit-mode only by default — this flags an indicator for review, it does not block.

## Acceptance criteria
- [ ] Text containing Tags-block code points or the targeted zero-width-joiner pattern is
      flagged (audit alert, not a block).
- [ ] Clean text incurs no false positive.
- [ ] Unit test covering both cases.
- [ ] Does not merge before issues #7–#11 (Phase 1/2) have shipped and been benchmarked —
      confirm this in the PR description.

## Labels
`good-first-issue`, `ai-llm-boundary`, `difficulty:medium`, `blocked-on-phase-gate`
```

</details>

---

## Guard unit-test gaps (no new production code)

Not a "raise coverage to N%" issue — that bar invites low-value filler tests, and this repo
has no CI gate on the number anyway (`build.yml` uploads to Codecov with
`fail_ci_if_error: false`). This is the opposite: five concrete, named gaps found by checking
which classes have no dedicated test file at all, not by reading a percentage.

Every `*DetectionEngine` in `src/Rasp.Core/Engine/` has its own `*DetectionEngineTests.cs`.
The `Guard` classes in `src/Rasp.Core/Guard/` — the layer that decides block-vs-audit, builds
the alert payload, and records metrics on top of an engine — mostly don't:
`CommandInjectionGuard`, `DeserializationGuard`, `PathTraversalGuard`, and `SsrfGuard` have no
dedicated test file, only indirect coverage through integration suites
(`RaspEntityFrameworkIntegrationTests`, `RaspHttpClientTests`, `RaspRuntimePatchingTests`,
`RaspAdoNetTests`). `SqlSinkGuard` has one test file,
`Rasp.Core.Tests/Guard/SqlSinkGuardTaintTests.cs`, but it only exercises the taint-enrichment
path — not the guard's own block/audit/no-threat branches. That file is also the pattern to
copy for all five issues below: `NoOpRaspMetrics` fake, a real `RaspAlertBus`,
`Options.Create(new RaspOptions {...})`, `NullLogger<T>.Instance`.

Each of the five issues is: for the named guard, cover (a) threat detected + audit mode —
alert pushed via the bus, no exception, (b) threat detected + block mode —
`RaspSecurityException` thrown, alert still pushed before the throw, (c) no threat — no
alert, no exception, (d) the guard's own early-return no-op (null/empty input never reaches
the engine or calls `_metrics.RecordInspection`).

### 14. `CommandInjectionGuardTests`

`AnalyzeProcessExecution(executablePath, arguments, useShellExecute, context)`
(`src/Rasp.Core/Guard/CommandInjectionGuard.cs`), gated by
`RaspOptions.BlockOnRuntimePatchingDetection`. No-op case: empty `executablePath`.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Add unit tests for `CommandInjectionGuard`

## Summary
`CommandInjectionGuard` has no dedicated unit test file — only indirect coverage via
integration tests. Add `Rasp.Core.Tests/Guard/CommandInjectionGuardTests.cs` covering its
own block/audit/no-threat/no-op branches in isolation.

## Background
Every `*DetectionEngine` has a dedicated test file; most `Guard` classes don't. This is one
of five identical-shaped issues — see `docs/good-first-issues-dotnet.md` for the full list
and the shared rationale (this is about naming concrete gaps, not chasing a coverage
percentage).

## Pattern to copy
`Rasp.Core.Tests/Guard/SqlSinkGuardTaintTests.cs` — `NoOpRaspMetrics` fake, a real
`RaspAlertBus`, `Options.Create(new RaspOptions {...})`, `NullLogger<T>.Instance`.

## What to test
`AnalyzeProcessExecution(executablePath, arguments, useShellExecute, context)`
(`src/Rasp.Core/Guard/CommandInjectionGuard.cs`), gated by
`RaspOptions.BlockOnRuntimePatchingDetection`:
- [ ] Threat detected + audit mode: alert pushed via `RaspAlertBus`, no exception thrown.
- [ ] Threat detected + block mode: `RaspSecurityException` thrown, alert still pushed
      before the throw.
- [ ] No threat: no alert, no exception.
- [ ] No-op case: empty `executablePath` never reaches the engine or calls
      `_metrics.RecordInspection`.

## Labels
`good-first-issue`, `testing`, `difficulty:easy`
```

</details>

### 15. `DeserializationGuardTests`

`AnalyzeType(Type?, context)` (`src/Rasp.Core/Guard/DeserializationGuard.cs`), gated by
`RaspOptions.BlockOnDetection`. No-op case: `null` type.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Add unit tests for `DeserializationGuard`

## Summary
`DeserializationGuard` has no dedicated unit test file — only indirect coverage via
integration tests. Add `Rasp.Core.Tests/Guard/DeserializationGuardTests.cs` covering its own
block/audit/no-threat/no-op branches in isolation.

## Background
Every `*DetectionEngine` has a dedicated test file; most `Guard` classes don't. This is one
of five identical-shaped issues — see `docs/good-first-issues-dotnet.md` for the full list
and the shared rationale (this is about naming concrete gaps, not chasing a coverage
percentage).

## Pattern to copy
`Rasp.Core.Tests/Guard/SqlSinkGuardTaintTests.cs` — `NoOpRaspMetrics` fake, a real
`RaspAlertBus`, `Options.Create(new RaspOptions {...})`, `NullLogger<T>.Instance`.

## What to test
`AnalyzeType(Type? typeToDeserialize, context)`
(`src/Rasp.Core/Guard/DeserializationGuard.cs`), gated by `RaspOptions.BlockOnDetection`:
- [ ] Threat detected + audit mode: alert pushed via `RaspAlertBus`, no exception thrown.
- [ ] Threat detected + block mode: `RaspSecurityException` thrown, alert still pushed
      before the throw.
- [ ] No threat: no alert, no exception.
- [ ] No-op case: `null` type never reaches the engine or calls
      `_metrics.RecordInspection`.

## Labels
`good-first-issue`, `testing`, `difficulty:easy`
```

</details>

### 16. `PathTraversalGuardTests`

`AnalyzePath(path, context)` (`src/Rasp.Core/Guard/PathTraversalGuard.cs`), gated by
`RaspOptions.BlockOnRuntimePatchingDetection`. No-op case: `null`/whitespace path.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Add unit tests for `PathTraversalGuard`

## Summary
`PathTraversalGuard` has no dedicated unit test file — only indirect coverage via
integration tests. Add `Rasp.Core.Tests/Guard/PathTraversalGuardTests.cs` covering its own
block/audit/no-threat/no-op branches in isolation.

## Background
Every `*DetectionEngine` has a dedicated test file; most `Guard` classes don't. This is one
of five identical-shaped issues — see `docs/good-first-issues-dotnet.md` for the full list
and the shared rationale (this is about naming concrete gaps, not chasing a coverage
percentage).

## Pattern to copy
`Rasp.Core.Tests/Guard/SqlSinkGuardTaintTests.cs` — `NoOpRaspMetrics` fake, a real
`RaspAlertBus`, `Options.Create(new RaspOptions {...})`, `NullLogger<T>.Instance`.

## What to test
`AnalyzePath(string path, context)` (`src/Rasp.Core/Guard/PathTraversalGuard.cs`), gated by
`RaspOptions.BlockOnRuntimePatchingDetection`:
- [ ] Threat detected + audit mode: alert pushed via `RaspAlertBus`, no exception thrown.
- [ ] Threat detected + block mode: `RaspSecurityException` thrown, alert still pushed
      before the throw.
- [ ] No threat: no alert, no exception.
- [ ] No-op case: `null`/whitespace path never reaches the engine or calls
      `_metrics.RecordInspection`.

## Labels
`good-first-issue`, `testing`, `difficulty:easy`
```

</details>

### 17. `SsrfGuardTests`

Two public entry points to cover, not one: `AnalyzeUri(Uri?, context)` and
`AnalyzeIp(IPAddress, context)` (`src/Rasp.Core/Guard/SsrfGuard.cs`), both gated by
`RaspOptions.BlockOnSsrfDetection`. No-op cases: `null` URI, `null` IP.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Add unit tests for `SsrfGuard`

## Summary
`SsrfGuard` has no dedicated unit test file — only indirect coverage via integration tests.
Add `Rasp.Core.Tests/Guard/SsrfGuardTests.cs` covering both of its public entry points'
block/audit/no-threat/no-op branches in isolation.

## Background
Every `*DetectionEngine` has a dedicated test file; most `Guard` classes don't. This is one
of five identical-shaped issues — see `docs/good-first-issues-dotnet.md` for the full list
and the shared rationale (this is about naming concrete gaps, not chasing a coverage
percentage). `SsrfGuard` has two public methods to cover, unlike the other four guards in
this set, which have one.

## Pattern to copy
`Rasp.Core.Tests/Guard/SqlSinkGuardTaintTests.cs` — `NoOpRaspMetrics` fake, a real
`RaspAlertBus`, `Options.Create(new RaspOptions {...})`, `NullLogger<T>.Instance`.

## What to test
Both `AnalyzeUri(Uri? requestUri, context)` and `AnalyzeIp(IPAddress ip, context)`
(`src/Rasp.Core/Guard/SsrfGuard.cs`), both gated by `RaspOptions.BlockOnSsrfDetection`:
- [ ] Threat detected + audit mode (each method): alert pushed via `RaspAlertBus`, no
      exception thrown.
- [ ] Threat detected + block mode (each method): `RaspSecurityException` thrown, alert
      still pushed before the throw.
- [ ] No threat (each method): no alert, no exception.
- [ ] No-op cases: `null` URI for `AnalyzeUri`, `null` IP for `AnalyzeIp` — neither reaches
      the engine or calls `_metrics.RecordInspection`.

## Labels
`good-first-issue`, `testing`, `difficulty:easy`
```

</details>

### 18. `SqlSinkGuardTests` (extends the existing taint file, doesn't replace it)

`AnalyzeCommand(commandText, context)` (`src/Rasp.Core/Guard/SqlSinkGuard.cs`)'s own
block/audit/no-threat branches, gated by `RaspOptions.BlockOnDetection` — the taint file
already covers the `[Tainted]` enrichment tag but never asserts on the block-vs-audit
decision itself in isolation. Add a new `SqlSinkGuardTests.cs` alongside
`SqlSinkGuardTaintTests.cs` rather than growing the taint file with unrelated assertions.

One thing worth flagging in whichever PR lands first: `NoOpRaspMetrics` is currently defined
inline in `SqlSinkGuardTaintTests.cs`. Move it to a shared test helper once a second file
needs it, rather than each of these five issues copy-pasting its own private copy.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Add `SqlSinkGuardTests` covering block/audit/no-threat branches (separate from the taint tests)

## Summary
`SqlSinkGuard` has one test file, `SqlSinkGuardTaintTests.cs`, but it only exercises the
`[Tainted]` enrichment tag — never the guard's own block/audit/no-threat decision in
isolation. Add a new `Rasp.Core.Tests/Guard/SqlSinkGuardTests.cs` alongside it (don't grow
the taint file with unrelated assertions).

## Background
Every `*DetectionEngine` has a dedicated test file; most `Guard` classes don't, and even
`SqlSinkGuard`'s existing test file is narrowly scoped. This is one of five identical-shaped
issues — see `docs/good-first-issues-dotnet.md` for the full list and the shared rationale
(this is about naming concrete gaps, not chasing a coverage percentage).

## Pattern to copy
`Rasp.Core.Tests/Guard/SqlSinkGuardTaintTests.cs` itself — `NoOpRaspMetrics` fake, a real
`RaspAlertBus`, `Options.Create(new RaspOptions {...})`, `NullLogger<T>.Instance`. Reuse
`NoOpRaspMetrics` from that file rather than redefining it (or, if convenient, move it to a
shared test helper as part of this PR — flag the decision either way).

## What to test
`AnalyzeCommand(commandText, context)` (`src/Rasp.Core/Guard/SqlSinkGuard.cs`)'s own
decision branches, gated by `RaspOptions.BlockOnDetection` — separate from (and in addition
to) the existing taint-enrichment coverage:
- [ ] Threat detected + audit mode: alert pushed via `RaspAlertBus`, no exception thrown.
- [ ] Threat detected + block mode: `RaspSecurityException` thrown, alert still pushed
      before the throw.
- [ ] No threat: no alert, no exception.
- [ ] New file added as `SqlSinkGuardTests.cs`, not merged into `SqlSinkGuardTaintTests.cs`.

## Labels
`good-first-issue`, `testing`, `difficulty:easy`
```

</details>

---

## Suggested order for a new contributor

`good-first-issues.md` issue 1 or 3 (Concat 3-arg, or `Trim()`), #4 here (the response-size
cap), or any of #14–#18 (the guard unit tests) are the smallest, most self-contained starting
points across both backlogs — each is a single new file plus a unit test, no cross-cutting
wiring. The guard-test issues are arguably the gentlest of all: zero new production code, one
existing file to copy almost line for line. #2 (the LDAP guard) is well-scoped too but isn't
startable until the `LdapInjectionDetectionEngine` feature work above lands.
