# ADR 001: Composite Architecture Strategy

**Status:** Accepted

## Context
Developing a Runtime Application Self-Protection (RASP) SDK alongside a target application requires frequent context switching between the library code and the implementation code. Traditional NuGet package references make debugging difficult ("black box"), while a monolithic repository muddies the Git history of distinct projects.

## Decision
We will adopt a **Composite Architecture using Git Submodules**. The target application (`TargetApp`) will be included as a submodule within the main SDK repository, but built using a unified solution file.

## Consequences

### Positive
* **Unified Debugging ("God Mode"):** Allows stepping through SDK code directly from the Target App execution without symbol server configuration.
* **Clean Separation:** Keeps the Git history of the SDK and the Target App completely separate, facilitating future decoupling.
* **Version Control:** Locks the testing app to specific commits of the SDK, ensuring reproducible benchmarks.

### Negative
* **Onboarding Friction:** Initial cloning requires the `--recursive` flag.
* **Maintenance:** Updates to the submodule require explicit `git submodule update` commands.

### Mitigation
* A specific Troubleshooting section has been added to the README.
* CI pipelines use `actions/checkout@v4` with `submodules: recursive` to handle this automatically.