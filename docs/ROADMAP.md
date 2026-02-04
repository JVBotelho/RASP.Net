# 🗺️ Product Roadmap

> **Vision:** To engineer the definitive standard for high-performance managed security in .NET, delivering a RASP with negligible runtime overhead (< 5ns on the hot path) and absolute zero-allocation where performance is critical.


## 🚀 Current Status (The Foundation)
**Focus:** Core Engine Performance & Windows Integrity.

We have successfully delivered a production-grade RASP that defies the "security is slow" stereotype.
- **✅ Zero-Allocation Engine:** `SqlInjectionDetectionEngine` operates on `ReadOnlySpan<char>` with SIMD acceleration (AVX2 / AVX-512 when available), achieving **~4ns** overhead for safe traffic.
- **✅ Composite Architecture:** Unified "God Mode" debugging via Git Submodules ([ADR 001](ADR/001-composite-architecture.md)).
- **✅ gRPC Integration:** Interceptors utilizing `IMessage.Descriptor` for dynamic but allocation-free field inspection ([ADR 002](ADR/002-detection-engine-evolution.md) - Phase 2).
- **✅ Windows Native Guard:** C++ sidecar for PEB manipulation detection and anti-debugging ([ADR 003](ADR/003-native-integrity-guard.md)).

---

## 📅 Near Term (The Lean Sentinel)
**Focus:** Memory Safety & Operational Stability.

Addressing the "Bleed" family of vulnerabilities (Heartbleed-style leaks) without the performance cost of statistical analysis.

- [ ] **Memory Disclosure Protection ([ADR 004](ADR/004-memory-disclosure-protection.md)):**
    - Implementation of the "Lean Sentinel" strategy.
    - **Response Size Hard Caps:** Deterministic blocking of bloated responses.
    - **Binary Pattern Scanning:** SIMD-based detection of immutable secrets (e.g., `sk_live_`, `xoxb-`) in outbound traffic.
    - **Debug Artifact Detection:** Scanning for `0xCDCD` / `0xABAB` heap patterns in production.

---

## 🔮 Future (The Architectural Shift)
**Focus:** Compile-Time Safety & Cross-Platform Dominance.

This release marks the transition from Runtime Introspection to Compile-Time Generation and Kernel-Level Monitoring.

### 1. Source Generators (The "No-Touch" Runtime)
*Aligned with [ADR 002: Detection Engine Evolution](ADR/002-detection-engine-evolution.md)*

Currently, v1.0 uses `IMessage.Descriptor` to iterate Protobuf fields. While fast, it still incurs a minimal runtime cost for metadata lookup.
**Goal:** Eliminate the integration layer overhead completely.

- [ ] **Proto-to-RASP Generation:** Create a Roslyn Source Generator that reads `.proto` files or C# DTOs and generates static `Inspect(Request r)` methods.
- [ ] **Benefit:**
    - **Effectively zero runtime lookup cost:** No reflection, no descriptors. Direct property access (`req.Title`).
    - **Tree Shaking:** Only generate inspection code for fields marked as sensitive or string-based.
    - **Compile-Time Validation:** Fail the build if a sensitive field is missing a sanitizer.

### 2. Linux eBPF Monitor (The Native Frontier)
*Aligned with [ADR 003: Platform Matrix](ADR/003-native-integrity-guard.md)*

Currently, the RASP uses robust C++ hooks for Windows. Linux support is limited to managed `Debugger.IsAttached`.
**Goal:** Parity with Windows security features on Linux environments (Kubernetes/Docker).

- [ ] **eBPF Integration:** Inject verified BPF programs into the Linux kernel to monitor `ptrace` and other syscalls used by debuggers and dumpers.
- [ ] **Benefit:**
    - **Stealth:** Monitoring happens in kernel space, invisible to user-mode attackers.
    - **Performance:** Event-driven detection with zero context switching penalty for the .NET app.
    - **Container Awareness:** Detect container escape attempts or unauthorized namespace manipulation.

---

## 📊 Feature Matrix

| Feature | (Current) | (Planned) | (Future) |
| :--- | :---: | :---: | :---: |
| **SQLi/XSS Engine** | ✅ SIMD / Span | ✅ Refined Rules | ✅ |
| **Integration** | Dynamic (Descriptor) | Dynamic | **Source Generators** ⚡ |
| **Memory Guard** | ❌ | **Lean Sentinel** | Lean Sentinel + |
| **Windows Security** | ✅ Native C++ | ✅ Native C++ | ✅ Native C++ |
| **Linux Security** | ⚠️ Managed Only | ⚠️ Managed Only | **eBPF Kernel Hooks** 🐧 |
| **Allocation Policy** | Zero-Alloc (Hot Path) | Zero-Alloc | **Zero-Alloc (Total)** |