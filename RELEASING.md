# Releasing RASP.Net

RASP.Net follows a tag-driven versioning and release pipeline using Semantic Versioning (SemVer). This document outlines the release process and the SemVer policy for changes to the library.

## SemVer Policy

A security library carries an extra burden ordinary libraries don't: **a version bump can change what gets blocked in production**. Consumers doing a "safe" minor update must be able to trust that their block/audit posture didn't silently flip. 

For RASP.Net, the "public API" includes the *detection contract* — defaults, rule sets, and activation model — alongside the C# signatures:

| Change | Version bump | Reasoning |
|:---|:---|:---|
| Bug fix, no behavior change | **PATCH** | Standard. |
| New detection rules / new guard | **MINOR** | Additive, but **can change runtime behavior** — a request that passed yesterday may be blocked today. Never PATCH. |
| Loosening a default; changing block→audit (or audit→block) behavior | **MINOR** (at minimum) | A consumer's security posture changes without a code change on their side. Must be called out prominently in release notes. |
| Removing/renaming public API | **MAJOR** | Standard. |
| Changing the activation model (e.g. profiler or MonoMod patching becoming default-on) | **MAJOR** | Alters what runs inside the consumer's process — the highest-trust decision a RASP consumer makes. |
| Dropping a TFM (e.g. net8.0 at end-of-support) | **MAJOR** | Breaks consumers on that runtime. |

## Release Process

1. Releases are triggered exclusively via **GitHub Releases**. Do not use local `git push --tags`.
2. When a new release is published on GitHub with a tag starting with `v` (e.g., `v1.3.0`), the [Release workflow](.github/workflows/release.yml) is triggered, targeting the `release` GitHub Environment (requires manual approval from a required reviewer before publishing).
3. The workflow builds, tests, and packs the library using `MinVer` to automatically version the NuGet packages based on the tag.
4. The workflow generates a `CHANGELOG.md` based on Conventional Commits in the history and appends it to the GitHub Release.
5. The packages are pushed to NuGet.org using **Trusted Publishing** (OIDC) — no long-lived API key is stored as a secret. The workflow exchanges a short-lived GitHub OIDC token for a 1-hour NuGet API key at publish time, per the Trusted Publishing policy configured on nuget.org for this repository, workflow file, and `release` environment.

## One-Time Setup

- **nuget.org Trusted Publishing policy**: nuget.org account → *Trusted Publishing* → add a policy with Repository Owner `JVBotelho`, Repository `RASP.Net`, Workflow File `release.yml`, Environment `release`.
- **`NUGET_USER` secret/variable**: the nuget.org profile name (not email) used to log in via `NuGet/login@v1`.
- **`RASP_CORE_SNK_BASE64` secret**: base64-encoded private strong-name key, used to fully sign `Rasp.Core.dll` at release time (see `src/Rasp.Core/Rasp.Core.csproj`).
- **`release` GitHub Environment**: configured with required reviewers, so every publish needs manual approval.
