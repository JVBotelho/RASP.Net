using System;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rasp.Instrumentation.RuntimePatching.Patches;

namespace Rasp.Instrumentation.RuntimePatching;

#pragma warning disable CA1805, CA1848, CA1031
public static class RaspRuntimePatching
{
    private static bool _initialized;
    private static readonly object _lock = new();

    /// <summary>
    /// Initializes RASP Runtime Patching (Phase B).
    /// This should be called as early as possible in the application lifecycle,
    /// before any JIT inlining happens for I/O or Process operations.
    /// Example: The first line in Program.cs
    /// </summary>
    public static void Initialize(IServiceProvider serviceProvider)
    {
        if (_initialized) return;

        lock (_lock)
        {
            if (_initialized) return;

            var logger = serviceProvider.GetService<ILoggerFactory>()?.CreateLogger("RaspRuntimePatching");

            // Graceful Degradation for Native AOT
            if (!RuntimeFeature.IsDynamicCodeSupported)
            {
                logger?.LogWarning("RASP Runtime Patching is disabled because dynamic code generation (Native AOT) is not supported in this environment.");
                _initialized = true;
                return;
            }

                logger?.LogInformation("Initializing RASP Runtime Patching (MonoMod) for Path Traversal and Process Execution.");

                try
                {
                    FileStreamPatch.Apply(serviceProvider);
                }
                catch (Exception ex)
                {
                    logger?.LogCritical(ex, "Failed to apply FileStreamPatch. This may leave the application unprotected against File System threats.");
                }

                try
                {
                    ProcessStartPatch.Apply(serviceProvider);
                }
                catch (Exception ex)
                {
                    logger?.LogCritical(ex, "Failed to apply ProcessStartPatch. This may leave the application unprotected against Process Execution threats.");
                }

                logger?.LogInformation("RASP Runtime Patching applied successfully.");

            _initialized = true;
        }
    }
}
#pragma warning restore CA1805, CA1848, CA1031
