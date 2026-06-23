using System;
using System.Buffers;
using Microsoft.Extensions.Logging;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine.Sql;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

/// <summary>
/// A specialized detection engine for SQL Sink layers (e.g., Entity Framework Core).
/// Unlike <see cref="SqlInjectionDetectionEngine"/>, this engine expects valid SQL syntax
/// and focuses strictly on anomalies that legitimate ORMs do not generate:
/// literal tautologies, dangerous stacked queries, and comment breakouts.
/// </summary>
public class SqlSinkDetectionEngine : IDetectionEngine
{
    private static readonly SearchValues<char> DangerousChars = SearchValues.Create("-;1'");

    private const int MaxStackAllocSize = 1024;
    private const int MaxAnalysisLength = 8192;

    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload)) return DetectionResult.Safe();
        return Inspect(payload.AsSpan(), context);
    }

    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty) return DetectionResult.Safe();

        // Fast path: if there are no typical injection characters, it's safe.
        if (!payload.ContainsAny(DangerousChars)) return DetectionResult.Safe();

        if (payload.Length > MaxAnalysisLength)
        {
            return DetectionResult.Threat(
                threatType: "SQL Injection",
                description: "Command text length exceeds maximum analysis threshold",
                severity: ThreatSeverity.Critical,
                confidence: 1.0,
                matchedPattern: "PayloadLimit"
            );
        }

        // 1. Comment Breakout Analysis (on raw payload, to preserve newlines)
        if (HasCommentBreakout(payload))
        {
            return DetectionResult.Threat("SQL Injection", "Comment breakout detected in SQL command", ThreatSeverity.Critical, 1.0, "CommentBreakout");
        }

        // Normalize payload for further analysis
        char[]? rentedBuffer = null;
        Span<char> normalizedBuffer = payload.Length <= MaxStackAllocSize
            ? stackalloc char[payload.Length]
            : (rentedBuffer = ArrayPool<char>.Shared.Rent(payload.Length)).AsSpan(0, payload.Length);

        try
        {
            int written = SqlNormalizer.Normalize(payload, normalizedBuffer);
            var searchSpace = normalizedBuffer.Slice(0, written);

            // 2. Literal Tautologies
            if (HasTautology(searchSpace))
            {
                return DetectionResult.Threat("SQL Injection", "Literal tautology detected in SQL command", ThreatSeverity.Critical, 1.0, "Tautology");
            }

            // 3. Dangerous Stacked Queries
            if (HasDangerousStackedQuery(searchSpace))
            {
                return DetectionResult.Threat("SQL Injection", "Dangerous stacked query detected", ThreatSeverity.Critical, 1.0, "StackedQuery");
            }

            return DetectionResult.Safe();
        }
        finally
        {
            if (rentedBuffer != null)
            {
                ArrayPool<char>.Shared.Return(rentedBuffer);
            }
        }
    }

    private static bool HasCommentBreakout(ReadOnlySpan<char> payload)
    {
        int offset = 0;
        while (true)
        {
            int index = payload.Slice(offset).IndexOf("--");
            if (index < 0) break;

            int absoluteIndex = offset + index;
            
            // Check backwards to see if there is any non-whitespace before a newline
            bool isBreakout = false;
            for (int i = absoluteIndex - 1; i >= 0; i--)
            {
                char c = payload[i];
                if (c == '\n' || c == '\r') break; // Reached start of line
                if (!char.IsWhiteSpace(c))
                {
                    isBreakout = true;
                    break;
                }
            }

            if (isBreakout) return true;
            offset = absoluteIndex + 2;
        }

        return false;
    }

    private static bool HasTautology(ReadOnlySpan<char> normalized)
    {
        // In normalized form, spaces are collapsed to single spaces and string is lowercased.
        return normalized.Contains("or 1=1", StringComparison.Ordinal) ||
               normalized.Contains("or 1 = 1", StringComparison.Ordinal) ||
               normalized.Contains("or '1'='1'", StringComparison.Ordinal) ||
               normalized.Contains("or '1' = '1'", StringComparison.Ordinal) ||
               normalized.Contains("or ''=''", StringComparison.Ordinal) ||
               normalized.Contains("or \"\"=\"\"", StringComparison.Ordinal) ||
               normalized.Contains("or 'a'='a'", StringComparison.Ordinal) ||
               normalized.Contains("or \"a\"=\"a\"", StringComparison.Ordinal);
    }

    private static bool HasDangerousStackedQuery(ReadOnlySpan<char> normalized)
    {
        // EF Core batches using semicolons (e.g. `...;insertinto...`).
        // We flag semicolons followed by destructive or administrative commands.
        int offset = 0;
        while (true)
        {
            int index = normalized.Slice(offset).IndexOf(';');
            if (index < 0) break;

            int absoluteIndex = offset + index;
            if (absoluteIndex + 1 < normalized.Length)
            {
                var afterSemicolon = normalized.Slice(absoluteIndex + 1).TrimStart();
                if (afterSemicolon.StartsWith("drop", StringComparison.Ordinal) ||
                    afterSemicolon.StartsWith("alter", StringComparison.Ordinal) ||
                    afterSemicolon.StartsWith("truncate", StringComparison.Ordinal) ||
                    afterSemicolon.StartsWith("exec", StringComparison.Ordinal) ||
                    afterSemicolon.StartsWith("xp_", StringComparison.Ordinal) ||
                    afterSemicolon.StartsWith("waitfor", StringComparison.Ordinal))
                {
                    return true;
                }
            }

            offset = absoluteIndex + 1;
        }

        return false;
    }
}
