# ADR 011: The LLM Boundary as Source and Sink (`Rasp.Instrumentation.Ai`)

**Date:** 2026-07-06
**Status:** 🟡 Proposed
**Priority:** Medium — Stage 3 feature track; must not start before the ADR 008/009 packaging work ships
**Builds on:** [ADR 006](006-sink-instrumentation-strategy.md) (sink pivot, taint tracking), [ADR 007](007-execution-context.md) (per-request provenance), [ADR 008](008-nuget-packaging.md) (the risk-boundary packaging split this package follows)

---

## Context

.NET services increasingly call LLMs in-process: `IChatClient` from `Microsoft.Extensions.AI`,
Semantic Kernel, the Azure OpenAI / OpenAI SDKs, or local ONNX models. From the RASP's point of
view this traffic is invisible today. An LLM response that ends up in an EF Core query, a
`Process.Start` argument, or an outbound URL is inspected by the existing sink guards on
*content* only — nothing records that the string came from a model, and nothing constrains what
a model-driven agent is allowed to execute.

Three external references frame the risk, and they agree on where enforcement belongs:

- **OWASP Top 10 for LLM Applications (2025).** LLM05 (Improper Output Handling) is the classic
  injection family with the model as the untrusted source — exactly the shape ADR 006's sinks
  already police. LLM06 (Excessive Agency) and LLM07 (System Prompt Leakage) are boundary
  problems: what the model may *do*, and what must not leave the process.
- **OWASP Top 10 for Agentic Applications (2026).** ASI02 (Tool Misuse), ASI03 (Privilege
  Abuse) and ASI05 (Unexpected Code Execution) all materialize at the moment an agent invokes a
  tool — a function call whose implementation bottoms out in the same SQL / process / file /
  HTTP sinks this RASP instruments.
- **Google SAIF.** Its risk map places prompt injection at the application layer and the
  controls for agent "rogue actions" at the action/orchestration layer — outside the model,
  at the point of execution.

The tempting reading of these lists is "add a prompt-injection detector". That reading is
rejected here, for the same reason ADR 006 rejected the embedded-WAF posture: classifying free
text at the perimeter is probabilistic, and published evasion work shows even the ML-based
classifiers (Prompt Shields, LLM Guard, LlamaFirewall) are bypassable. A regex engine claiming
to block LLM01 would be marketing, not detection, and it would contradict the measured-honesty
posture this project's benchmarks are built on.

What a sink-based RASP *can* do with ground truth: treat the model as an **untrusted source**
(its output is attacker-influenced whenever any attacker-readable content reached the prompt —
RAG documents, user messages, scraped pages) and treat the model call and the agent's tool
invocations as **instrumentable boundaries**. That is a provenance and enforcement problem, and
the plumbing for it — `RaspTaintSensor`, `RaspContext`, the sink guards — already exists.

---

## Decision

Ship a separate, opt-in package, **`Rasp.Instrumentation.Ai`**, following the ADR 008 risk
split (never a silent transitive dependency of the core). Scope is delivered in three phases,
ordered by how deterministic the mechanism is.

### Phase 1 — LLM output is a taint source

A `DelegatingChatClient` wrapper around `Microsoft.Extensions.AI.IChatClient` (plus a Semantic
Kernel function filter for that ecosystem) that:

1. Calls `RaspTaintSensor.MarkTainted(...)` on every text segment of the model response, the
   same call the perimeter already makes for inbound gRPC fields. No new taint machinery.
2. Stamps the current `RaspContext` (or synthesizes an orphan one, per ADR 007) so a later sink
   alert can say *"this SQL text derives from a model response in request X"* instead of only
   *"this SQL text is malicious"*.

The sink guards need no changes: they already inspect content unconditionally, and they already
read taint where the profiler is active. What Phase 1 adds is the missing provenance bit —
model output stops being indistinguishable from trusted application strings.

**Known limitation, stated up front:** taint *propagation* is the ADR 006 Phase C profiler,
currently Windows-only and limited to `String.Concat(string, string)`. Off Windows, taint
survives only when the exact string instance reaches the sink. Content inspection at the sink
is unaffected either way — this limits the quality of the alert, not the ability to block.
Every propagation target added in Stage 4 widens this phase's reach at zero cost to this
package.

### Phase 2 — Tool-call guard (deterministic, this is the enforcement point)

For agentic use — `IChatClient` function calling and Semantic Kernel's
`IFunctionInvocationFilter` — a policy guard that runs *before* the tool executes:

- **Allowlist / denylist of invocable functions** per `RaspOptions` policy, with the same
  block-or-audit shape as every existing guard. An agent hijacked into calling a function the
  operator never listed is stopped regardless of how the hijack was phrased (LLM06, ASI02,
  ASI03).
- **Argument inspection** through the existing `IDetectionEngine` set — a tool argument is a
  string a hostile model output can shape, so it gets the same SQLi/command/path/SSRF scan an
  inbound gRPC field gets, before the tool body runs and *in addition to* the sink guard that
  fires inside it (defense in depth, both layers already exist).
- **System-prompt canary (LLM07).** An operator-configured marker string embedded in the system
  prompt; the response scanner blocks or alerts when it appears in output. Exact-match, SIMD
  `SearchValues` scan — the same mechanism class as Lean Sentinel's secret patterns
  ([ADR 004](004-memory-disclosure-protection.md)), and deterministic in a way "detect prompt
  leakage semantically" never is.

### Phase 3 — Inbound heuristics, and a pluggable classifier seam (probabilistic, opt-in)

Last because it is the weakest ground truth:

- A span-based scanner for the *deterministically detectable* subset of prompt-injection
  mechanics: invisible Unicode (the Tags block `U+E0000`–`U+E007F`, zero-width joiners used for
  instruction smuggling), suspicious base64 runs inside natural-language fields, and a
  maintained signature list of known jailbreak markers. Ships **audit-mode by default** —
  these are indicators, not verdicts.
- An `IPromptClassifier` seam so operators can wire an external service (Azure Prompt Shields,
  LLM Guard, a self-hosted model) as an async, out-of-band check. Documented plainly as outside
  the latency budget and outside our accuracy claims — the same honesty rule that keeps MonoMod
  opt-in.

### Performance posture

Nothing in this package touches the existing hot path; a service that never references
`Rasp.Instrumentation.Ai` pays nothing. For services that do: an LLM round trip costs hundreds
of milliseconds, so the ADR 006 sink argument applies with orders of magnitude to spare — a
`MarkTainted` call and a `SearchValues` scan per response are noise against the network I/O
they ride on. The canary and heuristic scans must still be benchmarked and published like every
other guard; "obviously cheap" is a hypothesis until measured.

### Validation in the composite architecture

The victim app ([ADR 001](001-composite-architecture.md)) has no LLM surface. Add one endpoint
to `dotnet-grpc-library-api` backed by a **deterministic fake `IChatClient`** (scripted
responses, no real model, no network) so the attack suite can drive the full chain — poisoned
"model output" → tool call → sink — repeatably in CI. A red-team script (`attack/exploit_llm.py`)
exercises goal-hijack payloads against it, mirroring the existing XSS/SQLi suites.

---

## Coverage claim, kept honest

| List | Item | Claim |
|:---|:---|:---|
| LLM Top 10 2025 | LLM05 Improper Output Handling | **Primary target** — taint source + existing sink guards |
| LLM Top 10 2025 | LLM06 Excessive Agency | Tool-call allowlist (Phase 2) |
| LLM Top 10 2025 | LLM07 System Prompt Leakage | Canary scan (Phase 2), exact-match only |
| LLM Top 10 2025 | LLM01 Prompt Injection | **Partial, by design** — we constrain what injected output can execute; we do not claim to detect injection itself. Phase 3 heuristics are audit-grade indicators. |
| LLM Top 10 2025 | LLM02 Sensitive Information Disclosure | Egress side only, shared mechanism with Lean Sentinel (ADR 004) |
| Agentic Top 10 2026 | ASI02 / ASI03 / ASI05 | Tool-call guard + sink guards at the point of execution |
| Agentic Top 10 2026 | ASI06 Memory Poisoning, ASI04 Supply Chain | Out of scope — vector-store integrity and model provenance are different tooling categories |

---

## Consequences

### Positive ✅

- The differentiated capability is enforcement at the real sink with request-level provenance —
  something the classification-at-the-edge tools (AgentGuard, LLM Guard, vendor guardrails) do
  not do, and something this codebase gets almost for free from ADRs 006/007.
- Phases 1–2 are deterministic mechanisms with the same block-or-audit policy shape, alert
  plumbing, and benchmark discipline as every existing guard — no new architecture.
- The OWASP GenAI Security Project is the most active area of OWASP; a coverage table that maps
  to its lists strengthens the Stage 2 Incubator application ([ADR 010](010-owasp-incubator-submission.md))
  with material reviewers are currently looking for.
- Stage 4's taint-propagation widening now serves two consumers (classic injection *and* the AI
  boundary), improving its cost/benefit case.

### Negative ⚠️

- **Phase 3 is probabilistic and says so.** Heuristics will have false positives on legitimate
  text and false negatives against novel injections; signature lists rot and need maintenance.
  If this ships block-by-default it will burn operator trust.
- **API churn risk:** `Microsoft.Extensions.AI` is young and Semantic Kernel's filter API has
  already broken compatibility more than once. This package will track a faster-moving target
  than the BCL sinks do, so it multi-targets conservatively and pins its own dependency range.
- **Scope creep risk:** "AI security" is a large label; without the coverage table above acting
  as a fence, this package could absorb roadmap capacity that Stage 3's remaining classic rows
  (XXE, LDAP, Lean Sentinel) need.
- **Crowded space:** AgentGuard already does multi-tier prompt classification for .NET.
  Competing on classification would be entering someone else's game late — the scope here
  deliberately does not.

### Mitigations

- Phase order is a hard gate: no Phase 3 work before Phases 1–2 are shipped and benchmarked.
- Phase 3 is audit-only by default; turning it to block mode is an explicit operator decision,
  documented next to its false-positive characteristics.
- The fake-`IChatClient` validation endpoint keeps CI deterministic — no live model calls, no
  flaky accuracy assertions in the test suite.
- Signature list lives in one data file with its own conventional-commit scope, so its churn
  never destabilizes the guards' code.

---

## Alternatives Considered

| Alternative | Verdict |
|:---|:---|
| **In-process ML prompt classifier** | ❌ Breaks the zero-allocation, sub-µs identity of the product; accuracy claims we cannot stand behind; model weights become a supply-chain surface of our own. |
| **Perimeter prompt filtering only (embedded-WAF style)** | ❌ Re-litigates the exact posture ADR 006 moved away from, and misses indirect injection entirely — hostile instructions arriving via RAG documents or tool results never pass the inbound perimeter. |
| **Rely on vendor guardrails (Azure Content Safety, OpenAI moderation)** | ❌ As the *only* layer: they see the prompt, not the process — they cannot stop a poisoned response from reaching `Process.Start`, and they do not exist for self-hosted models. As one pluggable layer: that is exactly the Phase 3 seam. |
| **Fold into `Rasp.Core`** | ❌ Violates the ADR 008 risk boundary — most RASP adopters run no LLM traffic and must not carry `Microsoft.Extensions.AI` transitively. |
| **Do nothing** | ❌ LLM-consuming services are becoming a normal .NET workload; a RASP that cannot see the boundary leaves its newest untrusted source unlabeled. Deferring *is* reasonable — ignoring is not — hence Stage 3, not Stage 1. |

---

## Related ADRs

- [ADR 001](001-composite-architecture.md) — the victim app gains a fake-LLM endpoint so this package is validated the same way every guard is.
- [ADR 004](004-memory-disclosure-protection.md) — the canary/egress scan is the same mechanism class as Lean Sentinel's secret patterns; implementations should share the SIMD scanner.
- [ADR 006](006-sink-instrumentation-strategy.md) — the sink pivot and `RaspTaintSensor` are the foundation; this ADR adds a source, not a new detection philosophy.
- [ADR 007](007-execution-context.md) — `RaspContext` carries the "derives from model output in request X" provenance.
- [ADR 008](008-nuget-packaging.md) — opt-in packaging along the risk boundary; this package follows the MonoMod precedent.
- [ADR 010](010-owasp-incubator-submission.md) — GenAI coverage as supporting material for the Incubator → Lab progression.
