using System;
using Rasp.Core.Abstractions;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

/// <summary>
/// Composite detection engine that orchestrates multiple specialized engines.
/// Implements defense-in-depth by running SQL, XSS, and future detection engines in parallel.
/// </summary>
/// <remarks>
/// This pattern allows the RASP to detect multiple threat types simultaneously
/// while maintaining clean separation of concerns and testability.
/// </remarks>
public class CompositeDetectionEngine(
    SqlInjectionDetectionEngine sqlEngine,
    XssDetectionEngine xssEngine)
    : IDetectionEngine
{
    /// <summary>
    /// Runs all detection engines and returns the highest-severity threat found.
    /// String-based context compatibility overload.
    /// </summary>
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload))
            return DetectionResult.Safe();

        // Run all engines (order matters for performance: SQL is typically faster)
        var sqlResult = sqlEngine.Inspect(payload, context);
        if (sqlResult.IsThreat && sqlResult.Severity == ThreatSeverity.Critical)
        {
            // Short-circuit on critical SQL threats
            return sqlResult;
        }

        var xssResult = xssEngine.Inspect(payload, context);
        if (xssResult.IsThreat && xssResult.Severity == ThreatSeverity.Critical)
        {
            return xssResult;
        }

        // Return highest severity threat
        if (sqlResult.IsThreat && xssResult.IsThreat)
        {
            return sqlResult.Severity >= xssResult.Severity ? sqlResult : xssResult;
        }

        return sqlResult.IsThreat ? sqlResult : xssResult.IsThreat ? xssResult : DetectionResult.Safe();
    }

    /// <summary>
    /// Runs all detection engines using the Zero-Allocation Hot Path.
    /// </summary>
    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty) return DetectionResult.Safe();

        // 1. SQL Injection Check
        // The SQL Engine is generally faster (SIMD check on smaller charset), so we run it first.
        // We pass the payload directly. SQL engine ignores the XSS-specific context.
        // FIX: Pass string context "Unknown" to resolve overload ambiguity if the specific Enum overload is missing or implicit.
        var sqlResult = sqlEngine.Inspect(payload, "Unknown");
        if (sqlResult.IsThreat && sqlResult.Severity == ThreatSeverity.Critical)
        {
            return sqlResult;
        }

        // 2. XSS Check
        // The XSS engine uses the provided context to refine heuristics.
        var xssResult = xssEngine.Inspect(payload, context);
        if (xssResult.IsThreat && xssResult.Severity == ThreatSeverity.Critical)
        {
            return xssResult;
        }

        // Combine results (Highest Severity Wins)
        if (sqlResult.IsThreat && xssResult.IsThreat)
        {
            return sqlResult.Severity >= xssResult.Severity ? sqlResult : xssResult;
        }

        return sqlResult.IsThreat ? sqlResult : xssResult.IsThreat ? xssResult : DetectionResult.Safe();
    }
}