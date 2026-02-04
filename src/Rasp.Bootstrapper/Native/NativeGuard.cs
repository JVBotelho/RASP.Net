using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;

namespace Rasp.Bootstrapper.Native;

internal static partial class NativeGuard
{
    private const string DllName = "Rasp.Native.Guard.dll";

    [LibraryImport(DllName)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int CheckEnvironment();

    public static void AssertIntegrity(ILogger logger)
    {
        try
        {
            logger.LogInformation("[RASP NATIVE] 🔍 Checking process integrity...");

            var status = CheckEnvironment();

            if (status != 0)
            {
                var threat = status switch
                {
                    101 => "Basic Debugger (PEB Flag)",
                    102 => "Remote Debugger (Debug Port)",
                    _ => "Unknown Anomaly"
                };

                logger.LogCritical("[RASP NATIVE] 🚨 Integrity Violation! Threat: {ThreatCode} - {Desc}", status, threat);
                throw new System.Security.SecurityException($"RASP Integrity Violation: {threat}");
            }

            logger.LogInformation("[RASP NATIVE] ✅ Environment Clean. No debuggers detected.");
        }
        catch (DllNotFoundException)
        {
            logger.LogWarning("[RASP NATIVE] ⚠️ Guard DLL not found. Skipping OS-level checks.");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[RASP NATIVE] ❌ Failed to execute native checks.");
        }
    }
}