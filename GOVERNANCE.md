# Governance

RASP.Net is led by two project leaders. This document states the decision model, roles, and
continuity plan honestly for a project this size — it describes what actually happens today, not
an aspirational structure for a larger team.

## Leaders

| Leader | GitHub | Responsibilities |
|:---|:---|:---|
| João Victor Botelho Gonçalves | [@JVBotelho](https://github.com/JVBotelho) | Architecture and ADRs, detection engine design (managed guards, taint tracking), release authoring. |
| Eder Borella | [@EderBorella](https://github.com/EderBorella) | Second required reviewer on the `release` GitHub Environment ([RELEASING.md](RELEASING.md)) — no release publishes without this review. Repository collaborator with write access. |

Both leaders are repository collaborators with write access. Neither is acting on behalf of an
employer — this is a personal/hobby project for both, which is also why neither is affiliated
with the other through a shared employer (relevant to [ADR 010](docs/ADR/010-owasp-incubator-submission.md)'s
OWASP leadership requirement).

## Decision model

- **Day-to-day changes** (bug fixes, new detection rules within an existing guard, dependency
  bumps, docs): either leader can review and merge via the normal PR process
  ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **Architecturally significant changes** (new guard categories, changes to the activation model,
  versioning/release policy changes): recorded as an [ADR](docs/ADR/) before or alongside the
  implementation. ADRs are the durable record of *why*, not just *what* — see the existing ADRs
  for the format.
- **Releases**: authored by either leader, but publishing requires the other leader's approval as
  the required reviewer on the `release` environment ([ADR 009](docs/ADR/009-versioning-and-release-pipeline.md)).
  This is a hard gate, not a convention — GitHub Environment protection enforces it.
- Disagreements are resolved by discussion between the two leaders; there is no larger body to
  escalate to at this project's current size. If the leader set grows, this section will be
  updated to reflect a real decision process for that size, not before.

## Becoming a contributor

There is no formal committer ladder yet — the project is too small for one to mean anything real.
In practice: open a PR (see [CONTRIBUTING.md](CONTRIBUTING.md) and the seeded
[good-first-issues](docs/good-first-issues.md) backlog for a starting point). Contributors who
send several substantive, well-scoped PRs are the natural candidates to be invited as repository
collaborators or, eventually, project leaders — the same path the current second leader took.

## Access continuity (bus factor)

Bus factor is currently **2**. Concretely, if either leader becomes unavailable:

- The other leader already has full write access to the repository, admin rights, and required
  reviewer status — they can create/close issues, merge PRs, and cut a release without waiting on
  anyone.
- Release secrets and their recovery process (NuGet Trusted Publishing policy, the
  `RASP_CORE_SNK_BASE64` signing key) are documented in [RELEASING.md](RELEASING.md)'s "One-Time
  Setup" section — not held exclusively in one person's head or credentials.
- What is **not** yet distributed: sole ownership of the `github.com/JVBotelho` account hosting
  the repository. If that becomes a real risk (rather than a theoretical one), the mitigation is
  transferring the repository to a shared organization — tracked as a known gap, not solved today.

## Developer Certificate of Origin

By submitting a pull request, a contributor certifies the
[Developer Certificate of Origin](https://developercertificate.org/) — that they wrote the
contribution or otherwise have the right to submit it under the project's license
([MIT](LICENSE)). Sign off commits with `git commit -s` where practical; this is not yet enforced
by an automated check.

## Code of Conduct

RASP.Net follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Enforcement contact:
contact.faceted286@passinbox.com.
