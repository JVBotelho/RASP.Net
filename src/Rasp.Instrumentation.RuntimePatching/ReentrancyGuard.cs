using System;

namespace Rasp.Instrumentation.RuntimePatching;

/// <summary>
/// Prevents infinite recursion (reentrancy) when the RASP hooks 
/// trigger operations that are themselves hooked.
/// Because our detours run in a synchronous context (FileStream..ctor, Process.Start),
/// a ThreadStatic variable is sufficient and highly performant.
/// </summary>
#pragma warning disable CA1034, CA1815
public static class ReentrancyGuard
{
    [ThreadStatic]
    private static bool _inGuard;

    /// <summary>
    /// Checks if the current thread is already executing inside a hook.
    /// </summary>
    public static bool IsInGuard => _inGuard;

    /// <summary>
    /// Enters the guard. Disposing the returned struct exits the guard.
    /// </summary>
    public static GuardScope Enter()
    {
        return new GuardScope();
    }

    public readonly struct GuardScope : IDisposable
    {
        private readonly bool _wasInGuard;

        public GuardScope()
        {
            _wasInGuard = _inGuard;
            _inGuard = true;
        }

        public void Dispose()
        {
            _inGuard = _wasInGuard;
        }
    }
#pragma warning restore CA1034, CA1815
}
