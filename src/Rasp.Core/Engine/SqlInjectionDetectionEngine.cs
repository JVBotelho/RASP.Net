using System.Buffers;
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
public class SqlInjectionDetectionEngine(ILogger<SqlInjectionDetectionEngine> logger) : IDetectionEngine
{
    private static readonly SearchValues<char> DangerousChars =
        SearchValues.Create("'-;/*");

    private const int MaxStackAllocSize = 1024;
    private const int MaxAnalysisLength = 4096;

    /// <summary>
    /// Inspects the provided payload for SQL Injection patterns.
    /// </summary>
    /// <param name="payload">The raw input string to analyze (e.g., a query parameter or JSON field).</param>
    /// <param name="context">Metadata describing the source of the payload (e.g., "gRPC/CreateBook") for logging purposes.</param>
    /// <returns>
    /// A <see cref="DetectionResult"/> indicating whether the payload is safe or contains a threat.
    /// </returns>
    /// <remarks>
    /// <b>Performance Characteristics:</b>
    /// <list type="bullet">
    /// <item>
    ///     <description><b>Fast Path (SIMD):</b> Uses <see cref="SearchValues{T}"/> to scan for dangerous characters (e.g., quotes, comments). 
    ///     Safe inputs return immediately with near-zero overhead (~4ns).</description>
    /// </item>
    /// <item>
    ///     <description><b>Zero-Allocation:</b> Uses <c>stackalloc</c> for buffers under 1KB. For larger payloads, 
    ///     it rents from <see cref="ArrayPool{T}"/> to avoid GC pressure.</description>
    /// </item>
    /// <item>
    ///     <description><b>DoS Protection:</b> Inputs larger than 4KB are truncated before analysis to guarantee bounded execution time.</description>
    /// </item>
    /// </list>
    /// </remarks>
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload))
            return DetectionResult.Safe();

        var inputSpan = payload.AsSpan();

        // Fast Path (SIMD)
        if (!inputSpan.ContainsAny(DangerousChars))
        {
            return DetectionResult.Safe();
        }

        // DoS Protection
        if (inputSpan.Length > MaxAnalysisLength)
        {
            inputSpan = inputSpan.Slice(0, MaxAnalysisLength);
        }

        char[]? rentedBuffer = null;
        Span<char> normalizedBuffer = inputSpan.Length <= MaxStackAllocSize
            ? stackalloc char[inputSpan.Length]
            : (rentedBuffer = ArrayPool<char>.Shared.Rent(inputSpan.Length));

        try
        {
            int written = SqlNormalizer.Normalize(inputSpan, normalizedBuffer);
            var searchSpace = normalizedBuffer.Slice(0, written);

            double score = SqlHeuristics.CalculateScore(searchSpace);

            if (!(score >= 1.0)) return DetectionResult.Safe();
            logger.LogWarning("⚔️ RASP Blocked SQLi! Score: {Score} Context: {Context}", score, context);

            // FIX 2: Usando o Factory Method estático que resolve os erros de inicialização
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
}