using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine.Sql;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

/// <summary>
/// A high-performance detection engine for SQL Injection (SQLi) attacks.
/// <para>
/// This engine utilizes a hybrid approach combining SIMD-accelerated pre-filtering 
/// with heuristic analysis on normalized buffers to ensure minimal latency (nanosecond scale) 
/// and zero heap allocations for the vast majority of legitimate traffic.
/// </para>
/// </summary>
public partial class SqlInjectionDetectionEngine(ILogger<SqlInjectionDetectionEngine> logger) : IDetectionEngine
{
    private static readonly SearchValues<char> DangerousChars =
        SearchValues.Create("'-;/*");

    private const int MaxStackAllocSize = 1024;
    private const int MaxAnalysisLength = 4096;

    /// <summary>
    /// Inspects the provided payload for SQL Injection patterns.
    /// </summary>
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload))
            return DetectionResult.Safe();

        return Inspect(payload.AsSpan(), context);
    }

    /// <summary>
    /// Zero-Allocation interface implementation.
    /// Bridges the typed context to the internal logic (ignoring XSS context).
    /// </summary>
    public DetectionResult Inspect(ReadOnlySpan<char> payload, XssRenderContext context)
    {
        // SQL Injection detection is generally context-agnostic regarding HTML rendering.
        // We pass "Unknown" as metadata for logging purposes.
        return Inspect(payload, "Unknown");
    }

    /// <summary>
    /// Internal Core Logic using Span and String Context.
    /// </summary>
    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty)
            return DetectionResult.Safe();

        // Fast Path (SIMD)
        if (!payload.ContainsAny(DangerousChars))
        {
            return DetectionResult.Safe();
        }

        // DoS Protection
        if (payload.Length > MaxAnalysisLength)
        {
            payload = payload.Slice(0, MaxAnalysisLength);
        }

        char[]? rentedBuffer = null;
        Span<char> normalizedBuffer = payload.Length <= MaxStackAllocSize
            ? stackalloc char[payload.Length]
            : (rentedBuffer = ArrayPool<char>.Shared.Rent(payload.Length)).AsSpan(0, payload.Length);

        try
        {
            // Note: Ensure SqlNormalizer and SqlHeuristics exist in Rasp.Core.Engine.Sql
            int written = SqlNormalizer.Normalize(payload, normalizedBuffer);
            var searchSpace = normalizedBuffer.Slice(0, written);

            double score = SqlHeuristics.CalculateScore(searchSpace);

            if (!(score >= 1.0)) return DetectionResult.Safe();

            LogBlockedSqlInjection(logger, score, context);

            return DetectionResult.Threat(
                threatType: "SQL Injection",
                description: $"SQL Injection Patterns Detected (Score: {score})",
                severity: ThreatSeverity.High,
                confidence: 1.0,
                matchedPattern: "HeuristicScore"
            );
        }
        finally
        {
            if (rentedBuffer != null)
            {
                ArrayPool<char>.Shared.Return(rentedBuffer);
            }
        }
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Warning,
        Message = "⚔️ RASP Blocked SQLi! Score: {Score} Context: {Context}")]
    private static partial void LogBlockedSqlInjection(ILogger logger, double score, string context);
}