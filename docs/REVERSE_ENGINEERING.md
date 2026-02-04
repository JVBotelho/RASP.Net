# 🕵️ Reverse Engineering & Anti-Tamper Research

## 1. Executive Summary
This document analyzes the anti-debugging mechanisms implemented in `Rasp.Native.Guard.dll`, details known bypass techniques, and outlines the roadmap for advanced heuristic detection.
**Purpose:** Prove readiness against Reverse Engineers trying to analyze the game economy logic or create trainers.

---

## 2. Current Implementation Analysis (Layer 0)

The current version (v1.0) relies on standard Win32 APIs to detect the presence of a debugger.

| Technique | API Used | Detection Vector | Effectiveness |
| :--- | :--- | :--- | :--- |
| **PEB Flag** | `IsDebuggerPresent()` | Checks `PEB.BeingDebugged` byte. | 🟢 Low (Filters Script Kiddies) |
| **Debug Port** | `CheckRemoteDebuggerPresent()` | Checks for debug port attachment. | 🟡 Medium (Detects Managed Debuggers) |

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

## 4. Advanced Detection Roadmap (Phase 2)

To counter the bypasses above, Phase 2 will implement **heuristic detections** that are harder to spoof because they rely on CPU behavior rather than OS flags.

### 4.1. Timing Attacks (RDTSC / QPC)
**Theory:** Debuggers introduce significant latency when single-stepping or handling debug events. The CPU clock cannot be easily paused by user-mode debuggers.

**Implementation Strategy:**
Measure the CPU cycles consumed by a block of code. If the delta is suspiciously high, a debugger is likely interrupting the thread.

```cpp
// Prototype for Guard.cpp v2
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

### 4.2 Exception-Based Detection (SEH)

**Theory:** Debuggers intercept exceptions (like INT 3 or DBG_CONTROL_C) before the application's Structured Exception Handler (SEH) sees them.

**Implementation Strategy:** Raise a specific exception. If our __except block is NOT executed, it means a debugger swallowed the exception.

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