# ADR 003: Native Integrity Guard & Platform Matrix

**Status:** Accepted (Windows), Planned (Linux)

## Context
Managed code (.NET) cannot reliably detect environment tampering such as debugger attachment or memory patching by ring-3 actors if the runtime itself is compromised or instrumented. We need a native enforcement layer.

## Decision
Implement a hybrid platform strategy focusing on Windows first, with a specific roadmap for Linux.

* **Windows:** Native C++ sidecar (PEB inspection, Timing anomalies, Anti-Debug).
* **Linux:** Roadmap for eBPF kernel-level monitoring.
* **Fallback:** Managed .NET detection (`Debugger.IsAttached`) for all other environments.

## Justification (Why Windows First?)
* **Market Focus:** Dominance of Windows Server in our target high-scale segments (Gaming and Legacy Enterprise infrastructure).
* **API Stability:** Win32 APIs provide deep, stable hooks into process internals (PEB, NTAPI) that managed code cannot access directly or reliably.

## Consequences
* **Deployment:** Requires shipping native binaries alongside the managed DLLs.
* **Security:** Provides a defense-in-depth layer that persists even if the CLR is compromised.