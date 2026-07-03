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
/// Detection engine for Path Traversal attacks.
/// Uses a Fast-Path (Zero-Alloc) for clean, absolute paths within allowed roots,
/// and falls back to a Slow-Path using Ground-Truth resolution (Path.GetFullPath)
/// for suspicious or relative paths.
/// Limitations: Does not resolve symbolic links on the filesystem (as per ADR-006).
/// </summary>
public class PathTraversalDetectionEngine : IDetectionEngine
{
    private readonly RaspOptions _options;
    private readonly StringComparison _pathComparison;
    private readonly List<string> _canonicalAllowedRoots;

    public PathTraversalDetectionEngine(IOptions<RaspOptions> options)
    {
        _options = options?.Value ?? new RaspOptions();

        // OrdinalIgnoreCase is for Windows, Ordinal is for Linux/Mac
        _pathComparison = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        // Pre-cache canonical allowed roots with boundaries applied to enable zero-alloc fast-path
        _canonicalAllowedRoots = new List<string>();
        var configuredRoots = _options.AllowedFileRoots;
        if (configuredRoots != null)
        {
            foreach (var root in configuredRoots)
            {
                if (string.IsNullOrWhiteSpace(root)) continue;
                try
                {
                    string normalized = Path.GetFullPath(root);
                    if (!normalized.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal) &&
                        !normalized.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                    {
                        normalized += Path.DirectorySeparatorChar;
                    }
                    _canonicalAllowedRoots.Add(normalized);
                }
                catch (ArgumentException)
                {
                    // Skip misconfigured roots during setup
                }
            }
        }
    }

    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrWhiteSpace(payload)) return DetectionResult.Safe();
        return Inspect(payload.AsSpan(), context);
    }

    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        // If no roots are configured, we consider Path Traversal checks disabled.
        // As noted in review, this is a product decision to fail-open when not configured.
        if (_canonicalAllowedRoots.Count == 0)
        {
            return DetectionResult.Safe();
        }

        // --- Fast-Path (Zero-Alloc) ---
        // Only accept if we are absolutely certain. Any ambiguity falls to the slow path.
        if (Path.IsPathRooted(payload) &&
            !payload.Contains("..".AsSpan(), StringComparison.Ordinal) &&
            !payload.Contains("./".AsSpan(), StringComparison.Ordinal) &&
            !payload.Contains(".\\".AsSpan(), StringComparison.Ordinal))
        {
            foreach (var root in _canonicalAllowedRoots)
            {
                var rootSpan = root.AsSpan();

                // Fast boundary check without allocating strings
                if (payload.StartsWith(rootSpan, _pathComparison))
                {
                    return DetectionResult.Safe();
                }
            }
        }

        // --- Slow-Path (Allocates, resolves ground-truth) ---
        string payloadStr = payload.ToString();

        // Pre-validate invalid chars to prevent GetFullPath from throwing and causing exception-DoS
        if (payloadStr.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            return DetectionResult.Threat(
               "Path Traversal",
               "Path contains invalid characters",
               Enums.ThreatSeverity.High,
               1.0,
               payloadStr);
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(payloadStr);
        }
        catch (ArgumentException)
        {
            // If the path is so malformed it throws during GetFullPath, 
            // it's highly suspicious or invalid. We block to be safe.
            return DetectionResult.Threat(
                "Path Traversal",
                "Malformed path format",
                Enums.ThreatSeverity.High,
                1.0,
                payloadStr);
        }

        bool isAllowed = false;
        foreach (var root in _canonicalAllowedRoots)
        {
            var rootSpan = root.AsSpan();
            var fullPathSpan = fullPath.AsSpan();

            // Zero-allocation boundary check using slices
            if (fullPathSpan.StartsWith(rootSpan, _pathComparison))
            {
                isAllowed = true;
                break;
            }

            // If the full path exactly equals the root (without the trailing slash), it's also allowed
            if (rootSpan.Length > 0 &&
                fullPathSpan.Length == rootSpan.Length - 1 &&
                rootSpan.StartsWith(fullPathSpan, _pathComparison) &&
                (rootSpan[rootSpan.Length - 1] == Path.DirectorySeparatorChar || rootSpan[rootSpan.Length - 1] == Path.AltDirectorySeparatorChar))
            {
                isAllowed = true;
                break;
            }
        }

        if (!isAllowed)
        {
            return DetectionResult.Threat(
                "Path Traversal",
                "Path resolves outside allowed roots",
                Enums.ThreatSeverity.Critical,
                1.0,
                fullPath);
        }

        return DetectionResult.Safe();
    }
}
