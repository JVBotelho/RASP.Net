#include <windows.h>
#include <debugapi.h>

// RED TEAM NOTE:
// We use extern "C" to prevent C++ Name Mangling. 
// If we didn't, the function name would look like ?CheckEnvironment@@YAHXZ
// making it annoying to find via P/Invoke.

extern "C" __declspec(dllexport) int CheckEnvironment() {
    // CHECK 1: PEB BeingDebugged Flag
    // The most basic check. Reads a byte from the Process Environment Block.
    // Bypassed easily by attackers, but filters out script kiddies.
    if (IsDebuggerPresent()) {
        return 101; // Code 101: Basic Debugger Detected
    }

    // CHECK 2: Remote Debugger (Debug Port)
    // Checks if a debugger is attached to the process (like Managed Debuggers or VS).
    BOOL isRemoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger);
    
    if (isRemoteDebugger) {
        return 102; // Code 102: Remote Debugger Detected
    }

    // Future expansion: Check for specific process names (Wireshark, Cheat Engine)
    // or timing attacks (RDTSC) to detect slow-down caused by stepping.

    return 0; // CLEAN
}