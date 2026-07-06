# ADR 009: Versioning & Release Pipeline

**Date:** 2026-07-03
**Status:** ✅ Accepted & Implemented
**Priority:** High — a package without a versioning contract is worse than no package
**Builds on:** [ADR 008](008-nuget-packaging.md) (the packages this pipeline versions and publishes), [ADR 006](006-sink-instrumentation-strategy.md) (addendum point 5 — the CI signing hook this pipeline consumes)

---

## Context

The repository has no release process. The observable state:

- `<Version>1.0.5-elite</Version>` is hard-coded in three `.csproj` files (`Rasp.Core`,
  `Rasp.Bootstrapper`, `Rasp.Instrumentation.Grpc`); the other packable projects carry no version
  at all. Nothing keeps them in sync.
- `-elite` occupies the SemVer pre-release slot but isn't a pre-release: it orders alphabetically
  against real labels (`1.0.5-elite` sorts *after* `1.0.5-beta` and *before* stable `1.0.5`), so
  NuGet would resolve it as a pre-release of lower precedence than the stable release — the
  opposite of what a marketing suffix intends.
- No git tags exist, so no released state is reconstructible from history.
- Package versions drift across projects — `Google.Protobuf` is pinned to different versions in
  different `.csproj`s.
- Commit history already loosely follows Conventional Commits (`feat:`/`fix:`/`chore:`) but
  nothing enforces it and nothing consumes it.

A security library carries an extra burden ordinary libraries don't: **a version bump can change
what gets blocked in production**. Consumers doing a "safe" minor update must be able to trust
that their block/audit posture didn't silently flip. That makes the SemVer policy itself a
security-relevant decision, not release hygiene.

## Decision

Adopt tag-driven versioning with lockstep package versions, centralized dependency management,
and an explicit SemVer policy for detection-behavior changes.

### MinVer for tag-driven SemVer

[MinVer](https://github.com/adamralph/minver) computes the version from the latest git tag:
tagging `v1.1.0` produces packages versioned `1.1.0`; each commit after the tag produces
`1.1.1-alpha.0.N` automatically. All `<Version>` properties are deleted from `.csproj` files —
the tag is the single source of truth, and an un-tagged build can never masquerade as a release.

The `-elite` suffix is dropped from versions entirely; "Elite" stays README copy if wanted.
Pre-release labels are the standard, correctly-ordering set: `-alpha` → `-beta` → `-rc`.

All packages from [ADR 008](008-nuget-packaging.md)'s map version **in lockstep** — one tag, one
version number, ten packages. Independent per-package versioning gives a compatibility matrix
nobody asked for at this project size; lockstep means "RASP.Net 1.2.0" names one tested set.

### Central Package Management

A `Directory.Packages.props` at the repository root with
`ManagePackageVersionsCentrally=true`; every `PackageReference` version moves to a
`<PackageVersion>` entry. This mechanically eliminates the observed drift — a dependency version
can no longer differ between two projects because it is only written down once. The
intentionally-vulnerable demo target (`modules/`) is **excluded**: its pinned-vulnerable packages
are the point ([ADR 010](010-owasp-incubator-submission.md) covers its isolation).

### Conventional Commits → generated changelog

Commit-message linting in CI enforces the `feat:`/`fix:`/`chore:` convention the history already
uses informally. [git-cliff](https://github.com/orhun/git-cliff) generates `CHANGELOG.md` from
those messages at release time; nobody edits the changelog by hand.

### SemVer policy for a security library

The part that is project-specific. For RASP.Net, "public API" includes the *detection
contract* — defaults, rule sets, and activation model — alongside the C# signatures:

| Change | Version bump | Reasoning |
|:---|:---|:---|
| Bug fix, no behavior change | PATCH | Standard. |
| New detection rules / new guard | MINOR | Additive, but **can change runtime behavior** — a request that passed yesterday may be blocked today. Never PATCH. |
| Loosening a default; changing block→audit (or audit→block) behavior | MINOR **at minimum**, called out prominently in release notes | A consumer's security posture changes without a code change on their side. |
| Removing/renaming public API | MAJOR | Standard. |
| Changing the activation model (e.g. profiler or MonoMod patching becoming default-on) | MAJOR | Alters what runs inside the consumer's process — the highest-trust decision a RASP consumer makes. |
| Dropping a TFM (e.g. net8.0 at end-of-support) | MAJOR | Breaks consumers on that runtime. |

### Publish flow

Tag push (`v*`) triggers: build → full test matrix (both TFMs) → pack → sign (the hook from ADR
006 addendum point 5) → push to nuget.org → GitHub release with generated changelog. Publishing
requires a tag; no branch build can publish. The NuGet API key and signing material live as CI
secrets — which must be re-created after the OWASP repository transfer
([ADR 010](010-owasp-incubator-submission.md)).

## Consequences

### Implementation notes (2026-07-06)

The shipped pipeline deviates from the plan above in one deliberate way, and confirms the rest:

- **NuGet Trusted Publishing (OIDC) replaced the static `NUGET_API_KEY` secret.** nuget.org shipped
  Trusted Publishing for GitHub Actions after this ADR was written: the release workflow exchanges
  a short-lived GitHub OIDC token for a 1-hour NuGet API key at publish time
  (`NuGet/login@v1`), scoped to a nuget.org policy tied to this repository, the `release.yml`
  workflow file, and the `release` GitHub Environment. No long-lived NuGet credential is stored as
  a secret anywhere. This is a strictly stronger version of the "NuGet API key ... as CI secrets"
  language above and should be preferred over static keys going forward.
- **A `release` GitHub Environment with required reviewers** (any one of the project's two
  leaders, self-review disallowed) gates the publish job, adding a human approval step between
  "tag pushed to a reviewed GitHub Release" and "packages leave the building" — a second layer on
  top of the Alternatives-considered mitigation of not publishing from local `git push --tags`.
- `RASP_CORE_SNK_BASE64` signing and MinVer tag-driven versioning (`MinVerTagPrefix=v`) work as
  designed. First real release: `v1.2.0` (Rasp.Net, Rasp.Net.Core, and the other eight packages
  from [ADR 008](008-nuget-packaging.md)'s map), published via this pipeline.

### Positive ✅

- Releases are reproducible: any published version maps to exactly one tag and one commit.
- Version numbers stop being editable state — a class of "forgot to bump" and "bumped
  inconsistently" errors disappears.
- Dependency drift becomes structurally impossible for product projects.
- The SemVer table gives consumers (and OWASP reviewers) an explicit, auditable update contract:
  PATCH never changes what gets blocked.

### Negative ⚠️

- MinVer needs full git history — CI checkouts must use `fetch-depth: 0`, which is slower and
  easy to forget when adding new workflows.
- Lockstep versioning bumps packages whose contents didn't change; their changelogs will have
  empty-looking releases.
- Commit linting adds friction for drive-by contributors who haven't met Conventional Commits.
- Tag discipline is a human process; a mis-tag (e.g. tagging the wrong commit) publishes
  instantly. NuGet packages cannot be deleted, only unlisted.

### Mitigations

- A CI check on the release workflow asserts history depth before MinVer runs, failing loudly
  instead of producing a wrong `0.0.0-alpha` version.
- The PR template (arriving with [ADR 010](010-owasp-incubator-submission.md)'s community
  baseline) documents the commit format; the linter runs on PR titles so squash-merges stay
  clean regardless of individual commit messages.
- Release tags are created via a reviewed GitHub release (which creates the tag), not by local
  `git push --tags` — one less path to a fat-fingered publish.

## Alternatives Considered

| Alternative | Verdict |
|:---|:---|
| **Nerdbank.GitVersioning** | ❌ Solid, but wants a committed `version.json` and computes height-based versions; more machinery than a lockstep single-version project needs. MinVer's "the tag is the version" model is smaller and matches the intended workflow exactly. |
| **GitVersion** | ❌ Powerful branch-model inference, configuration-heavy; this project has no long-lived release branches to infer from. |
| **Manual `<Version>` per project (status quo)** | ❌ Already produced `-elite` and three-of-ten projects versioned. Demonstrated failure. |
| **Independent per-package versions** | ❌ Meaningful only when packages have independent lifecycles; here every release is one tested set, and the meta-package would need a version-pin matrix updated by hand. |
| **Floating dependency versions instead of CPM** | ❌ Non-deterministic restores are unacceptable for a security product; consumers must be able to reproduce the exact dependency closure of a release. |

## Related ADRs

- [ADR 006](006-sink-instrumentation-strategy.md) — addendum point 5 wired the signing hook this pipeline uses.
- [ADR 008](008-nuget-packaging.md) — defines the package set this pipeline versions in lockstep.
- [ADR 010](010-owasp-incubator-submission.md) — CI secrets and badge URLs must survive the post-acceptance repository transfer.
