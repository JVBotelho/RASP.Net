#include <windows.h>
#include <stdio.h>

// RED TEAM NOTES:
// 1. We use extern "C" to verify this is easily callable via P/Invoke.
// 2. We employ multiple overlapping techniques. Single checks are trivial to bypass.
// 3. Timing checks detect the overhead introduced by step-through debugging.

// Helper for Timing Attacks
bool CheckTimingAnomaly() {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    
    // High-resolution performance counter
    if (!QueryPerformanceFrequency(&frequency)) return false;
    
    QueryPerformanceCounter(&start);
    
    // Critical Section: A simple operation that should be instant.
    // If a debugger is stepping through or hooking this, it takes much longer.
    volatile int k = 0;
    for(int i = 0; i < 1000; i++) {
        k++;
    }

    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in microseconds
    double elapsed = (double)(end.QuadPart - start.QuadPart) * 1000000.0 / frequency.QuadPart;
    
    // Threshold: If it takes > 100ms (adjust based on profiling), something is interfering.
    // A normal CPU executes this in nanoseconds.
    return elapsed > 500.0; 
}

// Helper for Exception-Based Detection
// Debuggers often catch exceptions before the program does.
bool CheckExceptionHandler() {
    __try {
        // Raise a specific exception. If a debugger is attached, it might swallow it
        // or the timing of the handling will be off.
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true; // If we get here without entering the block below, logic is weird, but standard flow.
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // If we land here, the exception was handled by us, not a debugger.
        // This means "Process looks normal".
        return false; 
    }
    // If a debugger intercepts DBG_CONTROL_C, we might never reach here 
    // or behaviour is undefined, effectively breaking the analysis flow.
    return true;
}

extern "C" __declspec(dllexport) int CheckEnvironment() {
    // 1. Basic PEB Flag (The "Hello World" of Anti-Debug)
    if (IsDebuggerPresent()) {
        return 101; 
    }

    // 2. Remote Debugger (Managed Debuggers / VS Attach)
    BOOL isRemoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger);
    if (isRemoteDebugger) {
        return 102; 
    }

    // 3. Timing Anomaly (RDTSC/QPC) - Detects Stepping/Hooking overhead
    if (CheckTimingAnomaly()) {
        return 105; // Code 105: Timing Anomaly Detected
    }

    // 4. Exception Consumption check
    // DISABLED for this specific build to prevent false positives in some CI environments,
    // but code serves as proof of knowledge. Uncomment for strict mode.
    /* if (CheckExceptionHandler()) {
        return 106; 
    }
    */

    return 0; // CLEAN
}