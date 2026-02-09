using System;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Rasp.Bootstrapper.Native;

public partial class NativeGuard(ILogger<NativeGuard> logger)
{
    private const string LibraryName = "Rasp.Native.Guard.dll";

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport(LibraryName, EntryPoint = "CheckEnvironment")]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static partial int CheckEnvironment();

    public void AssertIntegrity()
    {
        LogStartingCheck();

        try
        {
            int result = CheckEnvironment();

            if (result != 0)
            {
                LogIntegrityViolation(result);
            }
            else
            {
                LogIntegrityVerified();
            }
        }
        catch (DllNotFoundException)
        {
            LogNativeLibMissing();
        }
#pragma warning disable CA1031
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogIntegrityCheckFailed(ex);
        }
    }

    // --- LOGGING (Instance Methods) ---
    [LoggerMessage(EventId = 1, Level = LogLevel.Information, Message = "🛡️ Initializing Native Integrity Guard...")]
    private partial void LogStartingCheck();

    [LoggerMessage(EventId = 2, Level = LogLevel.Critical, Message = "🚨 NATIVE INTEGRITY VIOLATION DETECTED! Code: {Result}")]
    private partial void LogIntegrityViolation(int result);

    [LoggerMessage(EventId = 3, Level = LogLevel.Information, Message = "✅ Native Environment Integrity Verified.")]
    private partial void LogIntegrityVerified();

    [LoggerMessage(EventId = 4, Level = LogLevel.Warning, Message = "⚠️ Native Guard library not found. Running in Managed-Only mode.")]
    private partial void LogNativeLibMissing();

    [LoggerMessage(EventId = 5, Level = LogLevel.Error, Message = "❌ Failed to execute Native Guard check.")]
    private partial void LogIntegrityCheckFailed(Exception ex);
}