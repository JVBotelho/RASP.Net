using System.Runtime.CompilerServices;
using Rasp.Core.Internal;

namespace Rasp.Core.Engine.Sql;

/// <summary>
/// Provides heuristic analysis to detect SQL Injection patterns in normalized strings.
/// Optimized for Zero-Allocation using ReadOnlySpan operations.
/// </summary>
internal static class SqlHeuristics
{
    // Threshold constants to avoid magic numbers
    private const double CriticalThreat = 1.0;
    private const double Safe = 0.0;

    // High-risk keywords: Structural SQL commands.
    // Detecting these implies a high probability of an injection attempt.
    private static readonly string[] HighRiskTokens =
    [
        "union select",
        "insert into",
        "delete from",
        "drop table",
        "exec(",
        "xp_cmdshell",
        "waitfor delay"
    ];

    private static readonly string[] ContextualPatterns =
    [
        "' or",
        "' and",
        "'or ",
        "'and ",
        "\" or",
        "\" and",
        "\"or ",
        "\"and ",
        "'=",
        "\"=",
        "';",
        "--",
        "/*"
    ];

    private static readonly MultiStringSearch _highRiskSearchValues =
        MultiStringSearch.Create(HighRiskTokens, StringComparison.OrdinalIgnoreCase);

    private static readonly MultiStringSearch _contextualSearchValues =
        MultiStringSearch.Create(ContextualPatterns, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Analyzes the input for SQL injection patterns.
    /// </summary>
    /// <param name="normalizedInput">The input string, already lowercased and space-collapsed.</param>
    /// <returns>
    /// A score indicating the threat level:
    /// <c>1.0</c> (CriticalThreat) for immediate blocking, 
    /// <c>0.0</c> (Safe) if no patterns are found.
    /// </returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static double CalculateScore(ReadOnlySpan<char> normalizedInput)
    {
        // 1. Contextual Pattern Analysis (High Confidence, Low False Positives)
        if (_contextualSearchValues.ContainsAny(normalizedInput))
        {
            return CriticalThreat;
        }

        // 2. High-Risk Token Analysis (Structural Keywords)
        if (_highRiskSearchValues.ContainsAny(normalizedInput))
        {
            return CriticalThreat;
        }

        return Safe;
    }
}