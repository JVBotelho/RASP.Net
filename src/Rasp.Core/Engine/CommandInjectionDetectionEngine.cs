using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Models;

namespace Rasp.Core.Engine;

/// <summary>
/// Detection engine for Command Injection and arbitrary Process Execution.
/// Adopts a Default-Deny allowlist approach for the executable name,
/// and applies lexical analysis on the arguments to prevent injection.
/// </summary>
public partial class CommandInjectionDetectionEngine : IDetectionEngine
{
    private readonly RaspOptions _options;

    // Common shell metacharacters that allow command chaining or subshells.
    private static readonly string[] ShellMetaCharacters = { "&", "|", ";", "$(", "`", "\\", "\n", "\r", ">", "<", "${" };

    [System.Text.RegularExpressions.GeneratedRegex(@"%[a-zA-Z0-9_]+%")]
    private static partial System.Text.RegularExpressions.Regex WindowsVariableRegex();

    private readonly List<string> _canonicalAllowedProcs = new();

    private static readonly HashSet<string> ShellInterpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "zsh", "dash", "ash", "csh", "ksh"
    };

    public CommandInjectionDetectionEngine(IOptions<RaspOptions> options)
    {
        _options = options?.Value ?? new RaspOptions();

        if (_options.AllowedProcesses != null)
        {
            foreach (var proc in _options.AllowedProcesses)
            {
                if (string.IsNullOrWhiteSpace(proc)) continue;
                try
                {
                    _canonicalAllowedProcs.Add(Path.GetFullPath(proc));
                }
                catch (ArgumentException)
                {
                    // Skip invalid configured paths
                }
            }
        }
    }

    // Legacy overload required by IDetectionEngine interface.
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        return Inspect(payload, Array.Empty<string>(), false, context);
    }

    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        return Inspect(payload.ToString(), context);
    }

    /// <summary>
    /// Inspects a process execution attempt with discrete arguments.
    /// </summary>
    public DetectionResult Inspect(string? executablePath, IReadOnlyList<string> arguments, bool useShellExecute, string context = "Unknown")
    {
        if (string.IsNullOrWhiteSpace(executablePath)) return DetectionResult.Safe();

        // 1. Verify Executable Allowlist (Default-Deny)
        if (_canonicalAllowedProcs.Count == 0)
        {
            return DetectionResult.Threat(
                "Command Injection",
                "Process execution blocked by default (Empty Allowlist)",
                Enums.ThreatSeverity.Critical,
                1.0,
                executablePath);
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(executablePath);
        }
        catch (ArgumentException)
        {
            return DetectionResult.Threat(
               "Command Injection",
               "Malformed executable path",
               Enums.ThreatSeverity.High,
               1.0,
               executablePath);
        }

        StringComparison comp = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        bool isAllowed = false;
        foreach (var canonicalAllowed in _canonicalAllowedProcs)
        {
            if (string.Equals(canonicalAllowed, fullPath, comp))
            {
                isAllowed = true;
                break;
            }
        }

        if (!isAllowed)
        {
            return DetectionResult.Threat(
                "Command Injection",
                "Executable not in allowlist",
                Enums.ThreatSeverity.Critical,
                1.0,
                executablePath);
        }

        // 2. Argument Analysis
        string fileName = Path.GetFileName(fullPath);
        bool isShellInterpreter = ShellInterpreters.Contains(fileName);

        // We only rigorously check metacharacters if UseShellExecute is true OR the binary is a shell.
        if ((useShellExecute || isShellInterpreter) && arguments != null && arguments.Count > 0)
        {
            foreach (var arg in arguments)
            {
                if (string.IsNullOrWhiteSpace(arg)) continue;

                foreach (var meta in ShellMetaCharacters)
                {
                    if (arg.Contains(meta, StringComparison.Ordinal))
                    {
                        return DetectionResult.Threat(
                            "Command Injection",
                            $"Dangerous shell metacharacter '{meta}' in arguments",
                            Enums.ThreatSeverity.High,
                            0.9,
                            arg);
                    }
                }

                if (WindowsVariableRegex().IsMatch(arg))
                {
                    return DetectionResult.Threat(
                        "Command Injection",
                        "Dangerous Windows variable expansion in arguments",
                        Enums.ThreatSeverity.High,
                        0.9,
                        arg);
                }
            }
        }

        return DetectionResult.Safe();
    }
}
