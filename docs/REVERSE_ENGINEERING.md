# 🕵️ Reverse Engineering & Anti-Tamper Research

## 1. Executive Summary
This document analyzes the anti-debugging mechanisms implemented in `Rasp.Native.Guard.dll`, details known bypass techniques, and outlines the roadmap for advanced heuristic detection.
**Purpose:** Prove readiness against Reverse Engineers trying to analyze the game economy logic or create trainers.

---

## 2. Current Implementation Analysis (Layer 0)

The current version relies on standard Win32 APIs plus a CPU-timing check, all live in
`Rasp.Native.Guard/Guard.cpp`'s `CheckEnvironment()`.

| Technique | API Used | Detection Vector | Effectiveness |
| :--- | :--- | :--- | :--- |
| **PEB Flag** | `IsDebuggerPresent()` | Checks `PEB.BeingDebugged` byte. | 🟢 Low (Filters Script Kiddies) |
| **Debug Port** | `CheckRemoteDebuggerPresent()` | Checks for debug port attachment. | 🟡 Medium (Detects Managed Debuggers) |
| **Timing Anomaly** | `QueryPerformanceCounter()` | Flags a tight loop taking >500µs, indicating single-stepping/hooking overhead. | 🟡 Medium (Detects interactive debugging) |

`CheckExceptionHandler()` (SEH-based detection, see §4.2) is implemented in `Guard.cpp` but
**disabled by default** — commented out to avoid false positives in some CI environments.

### 🔍 Self-Critique
While effective against casual attempts, these checks are **trivial to bypass** for an experienced Reverse Engineer. They serve as a "speed bump", not a wall.

---

## 3. Bypass Techniques (Red Team Perspective)

A determined attacker typically employs the following methods to neutralize our current defenses:

### 3.1. PEB Manipulation (The "ScyllaHide" Method)
The Process Environment Block (PEB) is a user-mode data structure writable by the process itself.
* **Attack:** An attacker injects code or uses a plugin (e.g., ScyllaHide for x64dbg) to set the `BeingDebugged` flag (offset `0x002`) to `0`.
* **Result:** `IsDebuggerPresent()` returns `false` even if a debugger is attached.

### 3.2. API Hooking (Detours)
* **Attack:** Using libraries like MinHook or Detours, attackers can hook `kernel32!CheckRemoteDebuggerPresent`.
* **Result:** The API always returns `0`, masking the debugger presence.

---

## 4. Heuristic Detections (Beyond OS Flags)

To counter the bypasses above, these detections rely on CPU behavior rather than OS flags. 4.1 is
implemented and active; 4.2 is implemented but disabled by default (see §2).

### 4.1. Timing Attacks (RDTSC / QPC) — Implemented
**Theory:** Debuggers introduce significant latency when single-stepping or handling debug events. The CPU clock cannot be easily paused by user-mode debuggers.

**Implementation:**
Measures the CPU cycles consumed by a block of code. If the delta is suspiciously high, a debugger is likely interrupting the thread. Live in `Guard.cpp`:

```cpp
bool CheckTimingAnomaly() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Critical Section: Fast operation
    // A debugger stepping here will cause a massive delay (ms vs ns)
    volatile int k = 0;
    for(int i = 0; i < 1000; i++) k++;

    QueryPerformanceCounter(&end);
    
    double elapsed_us = (double)(end.QuadPart - start.QuadPart) * 1000000.0 / freq.QuadPart;
    
    // Threshold: > 500us implies interference
    return elapsed_us > 500.0; 
}
```

### 4.2 Exception-Based Detection (SEH) — Implemented, disabled by default

**Theory:** Debuggers intercept exceptions (like INT 3 or DBG_CONTROL_C) before the application's Structured Exception Handler (SEH) sees them.

**Implementation:** Raise a specific exception. If our __except block is NOT executed, it means a debugger swallowed the exception. Present in `Guard.cpp` as `CheckExceptionHandler()`, commented out of the `CheckEnvironment()` call chain to avoid false positives in some CI environments.

```cpp
__try {
    RaiseException(DBG_CONTROL_C, 0, 0, NULL);
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // If we are here, we are SAFE (App handled the exception)
    return false; 
}
// If we reach here, DEBUGGER DETECTED (It swallowed the exception)
return true;
```

### 5. Conclusion
Moving from "Flag-based" to "Behavior-based" detection increases the complexity for attacker tooling. While no client-side protection is absolute, these measures protect the integrity of the game process during the critical startup phase.