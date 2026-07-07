# ADR 010: OWASP Incubator Submission — Pre-Submission Plan

**Date:** 2026-07-03
**Status:** 🟡 In Progress — items 1 and 4 (Passing) done; item 2 partial (governance docs landed,
templates outstanding); items 3, 5, 6 outstanding. Current focus: close 3/5/6 for submission —
Silver self-certification (item 4) explicitly deferred, not required.
**Priority:** High — Stage 2 of the roadmap; everything here happens *before* the application is filed
**Builds on:** [ADR 008](008-nuget-packaging.md) / [ADR 009](009-versioning-and-release-pipeline.md) (published, versioned packages are the maturity signal the application leans on)

---

## Context

The project's stated destination is OWASP Incubator, then Lab. The formal entry bar — open
source, vendor-neutral, security-focused — is already met: MIT license, a published
[threat model](../ATTACK_SCENARIOS.md), [SECURITY.md](../../SECURITY.md), and no corporate
steering. What is *not* met is the surrounding structure OWASP evaluates and, in two cases,
hard-requires:

1. **Leadership.** ✅ Resolved 2026-07-06. Current OWASP policy requires multiple project leaders,
   not all from the same employer, each with admin on the repository. RASP.Net now has a second
   leader, [@EderBorella](https://github.com/EderBorella), added as a repository collaborator and
   as a required reviewer on the `release` GitHub Environment (see [ADR 009](009-versioning-and-release-pipeline.md)) —
   so no release publishes without a second person's sign-off. Both leaders work on the project as
   a personal/hobby effort with no employer involved, which trivially satisfies "not all from the
   same employer" (OWASP) and `contributors_unassociated` (OSSF Gold, see item 4 below).
2. **The intentionally-vulnerable demo target.** `modules/dotnet-grpc-library-api` exists to be
   attacked; it pins known-vulnerable packages on purpose. To an OWASP reviewer (or any
   dependency scanner) glancing at the repository, those look like *product* dependencies unless
   the separation is unmistakable.
3. **Community machinery.** ✅ Partially resolved 2026-07-06: [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md)
   and [`GOVERNANCE.md`](../../GOVERNANCE.md) landed, and the `good-first-issue` backlog is the
   curated entry point for first-time contributors. Still open: issue/PR templates.
4. **Timing traps.** The `www-project-rasp-net` project-page repository is provisioned by the
   OWASP Foundation under `github.com/OWASP` only *after* acceptance — it cannot be created in
   advance. And after acceptance the main repository must transfer to `github.com/OWASP`, which
   silently drops Actions secrets and third-party integrations.

Review turnaround for Incubator applications is typically 4–8 weeks, so sequencing matters: the
slowest item (recruiting a second leader) has to start first.

## Decision

Treat the pre-submission work as an ordered workstream and file the application only when items
1–5 below are done. Ordered by lead time, longest first:

### 1. Recruit a second project leader (start immediately) — ✅ Done (2026-07-06)

The natural candidate is an engaged external contributor — someone who has already read the code
deeply enough to open a substantive issue or PR. The `good-first-issue` backlog (item 2) doubles
as the recruitment funnel: taint-propagation targets (each additional `string`
method the profiler should instrument) are ideal starter issues — small, well-scoped, with
`String.Concat` as an existing pattern to copy. The leader requirement is satisfied by a person,
not a checkbox, so this item has the most schedule risk and no shortcut.

**Resolution:** [@EderBorella](https://github.com/EderBorella) joined as second leader —
repository collaborator and required reviewer on the `release` environment. Bus factor is now 2,
unblocking both the OWASP leadership requirement and the OSSF Silver/Gold `bus_factor` criteria
(item 4). `roles_responsibilities` and `access_continuity` (OSSF Silver) are now written down in
item 2's `GOVERNANCE.md`, below.

### 2. Community baseline — partially done

- ✅ `CODE_OF_CONDUCT.md` — Contributor Covenant, unmodified; OWASP projects also inherit the OWASP
  Code of Conduct after acceptance, and the two coexist.
- ✅ `GOVERNANCE.md` — states the decision model (two leaders, informal consensus + ADRs for
  architecturally significant decisions), how a contributor becomes a committer, and access
  continuity / bus factor. Honest about present size rather than aspirational.
- Still open: issue templates (bug / detection gap / false positive — the last two being the report types a
  RASP uniquely attracts) and a PR template that documents the Conventional Commits format from
  [ADR 009](009-versioning-and-release-pipeline.md).
- ✅ Seeded `good-first-issue` backlog per item 1 — done 2026-07-06:
  [docs/good-first-issues.md](../good-first-issues.md) (taint-propagation targets, native profiler)
  and [docs/good-first-issues-dotnet.md](../good-first-issues-dotnet.md) (.NET-only OWASP Top 10
  gaps and the ADR 011 AI/LLM boundary). Filing these as actual GitHub issues is blocked on the
  issue templates above landing first.

### 3. Isolate the intentionally-vulnerable demo target

- A prominent warning block in the `modules/` README and the root README stating the submodule
  is a deliberately vulnerable test target, not part of the shipped product.
- A solution filter (`.slnf`) covering only product projects, so IDE-level dependency audits and
  `dotnet list package --vulnerable` runs against the product don't sweep in the victim app.
- Any dependency-scanning badge the product advertises points at the filtered product set,
  explicitly excluding `modules/`. The demo target stays out of Central Package Management
  ([ADR 009](009-versioning-and-release-pipeline.md)) for the same reason — its pins are
  intentionally wrong.

### 4. Start the OSSF Best Practices self-certification — ✅ Passing achieved (2026-07-06)

**Correction (2026-07-06):** OWASP's own Incubator → Lab maturity criteria do **not** require a
`bestpractices.dev` badge of any specific tier — the actual requirement, verified against OWASP's
project lifecycle page, is only *"Project registered and self-certification started."* The
original wording above ("a passing badge is a Lab-promotion criterion") overstated this. Starting
the questionnaire pre-submission is still worth doing — it's a questionnaire, most answers already
exist, and it surfaces gaps cheaply as a small PR instead of a review finding — but it was never a
hard gate on Incubator submission, and isn't one for Lab promotion either.

**Status:** [Passing badge #13510](https://www.bestpractices.dev/en/projects/13510) achieved
2026-07-06, embedded in the [README](../../README.md). This already exceeds what either OWASP stage
requires. Silver self-certification is in progress (governance docs landed —
[GOVERNANCE.md](../../GOVERNANCE.md), [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) — bus factor
2 resolved item 1's blocker on it) but has real remaining gaps (`test_statement_coverage80`,
`signed_releases`, `version_tags_signed`, `build_repeatable` — the last confirmed empirically
non-reproducible, not just unmeasured). **Since Silver is not required for submission, closing
those gaps is explicitly deferred until after Incubator submission** — current priority is items
3, 5, and 6 below. New code is nonetheless already held to a coverage bar approaching Gold
(`codecov.yml` patch target 90%) so day-to-day work walks toward Silver/Gold without spending
dedicated time on the badge itself right now.

### 5. Draft the OWASP project page in advance

Write the `index.md`, project description, and roadmap content for `www-project-rasp-net` now
and keep it in this repository (e.g. `docs/owasp-project-page/`) until the Foundation provisions
the real repo post-acceptance. Stale or empty project pages are what gets OWASP projects flagged
inactive; having the content ready means the page goes live the day the repository exists.

### 6. Submit

File through the official OWASP project application. Expect 4–8 weeks of review.

### Recorded here for completeness — post-acceptance obligations

Not pre-submission work, but decided now so nothing is discovered mid-transfer:

- **Repository transfer to `github.com/OWASP`** is mandatory (private accounts are not
  permitted). GitHub preserves stars, issues, history and redirects old URLs. What does *not*
  survive and needs manual re-creation: Actions secrets (NuGet API key, release signing key from
  [ADR 009](009-versioning-and-release-pipeline.md)), the Codecov integration, and badge URLs.
- The demo-target submodule stays on a personal account — it is test tooling, not the product,
  and keeping it out of the OWASP org reinforces item 3's separation.
- Populate `www-project-rasp-net` from the drafted content and keep it current with releases.

## Consequences

### Positive ✅

- OWASP affiliation gives the project vendor-neutral credibility that a personal-account
  repository cannot, and a recruitment surface (OWASP chapters, conferences) that directly feeds
  the bus-factor problem.
- The Incubator → Lab ladder gives Stage 3's coverage work an external progression metric.
- Governance artifacts and the OSSF questionnaire are durable assets regardless of the
  application's outcome.

### Negative ⚠️

- Repository ownership moves to an org the maintainer does not control; org-level policies
  (bots, required workflows, member rules) apply thereafter. The .NET Foundation option
  (Stage 4) is unaffected — OWASP mandates repo *location*, the Foundation only requires
  publicly accessible code — but the overlap of two governance regimes is real.
- ~~The second-leader requirement makes the submission date dependent on a person who doesn't
  exist yet. This is the plan's critical path and it is not fully under the maintainer's control.~~
  Resolved 2026-07-06 — see item 1. Remaining critical path is now item 2 (community/governance
  docs), which is fully within the maintainers' control and has no external dependency.
- Acceptance creates a permanent maintenance duty: OWASP flags projects with stale pages or no
  release activity as inactive, so Stage 2 quietly commits the project to a release cadence.

### Mitigations

- Item 1 started before everything else and ran in parallel with items 2–5; it closed 2026-07-06
  via direct outreach rather than waiting on the issue tracker.
- The transfer checklist (secrets, Codecov, badges) is written into the release runbook *before*
  acceptance, so nothing has to be discovered mid-transfer.
- The drafted project page doubles as the application's project description — the work is spent
  once, used twice.

## Alternatives Considered

| Alternative | Verdict |
|:---|:---|
| **Apply now, fix gaps during review** | ❌ The leader requirement gates the application itself; an application that fails a hard requirement burns reviewer goodwill and restarts the 4–8 week clock. |
| **.NET Foundation first, OWASP later** | ❌ The Foundation is a maturity seal, not a launch lever (roadmap, Stage 4): it wants published packages, adoption signals, and bus factor > 1 — all things OWASP-driven community growth is meant to produce, not consume. |
| **Stay independent indefinitely** | ❌ Works fine for a personal code repository, but the stated goal of a *vendor-neutral security standard* needs neutral ownership — and the single-maintainer bus factor never improves by itself. |
| **Remove the vulnerable demo target instead of isolating it** | ❌ The composite architecture ([ADR 001](001-composite-architecture.md)) is how the SDK is validated against a real application; deleting the victim app would gut the test story to simplify a reviewer's first impression. Isolation achieves the same clarity without the loss. |

## Related ADRs

- [ADR 001](001-composite-architecture.md) — the victim-app submodule this ADR isolates rather than removes.
- [ADR 008](008-nuget-packaging.md) — installable packages are the adoption evidence behind the application.
- [ADR 009](009-versioning-and-release-pipeline.md) — release discipline feeds the OSSF questionnaire; CI secrets must survive the repository transfer.
