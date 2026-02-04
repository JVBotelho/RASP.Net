using System.Runtime.CompilerServices;

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

    // Contextual patterns: Specific sequences targeting quote breakouts.
    // We prioritize these checks to solve the "O'Reilly" false positive problem:
    // we only flag quotes that are immediately followed by SQL syntax.
    private static readonly string[] ContextualPatterns =
    [
        "' or",   // Tautology: admin' OR '1'='1
        "' and",  // Tautology: admin' AND 1=1
        "'=",     // Arithmetic Tautology: '1'='1'
        "';",     // Query Stacking: '; DROP TABLE
        "--",     // Comment Truncation
        "/*"      // Inline Comment
    ];

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
        // We check these first because they represent the most common attack vectors (tautologies).
        // By looking for context (e.g., quote + operator), we avoid blocking names like "O'Reilly".
        foreach (var pattern in ContextualPatterns)
        {
            // Note: In .NET 9+, this loop could be replaced by SearchValues<string> for SIMD acceleration.
            // For now, linear scanning is acceptable as it remains Zero-Alloc.
            if (normalizedInput.Contains(pattern.AsSpan(), StringComparison.Ordinal))
            {
                return CriticalThreat;
            }
        }

        // 2. High-Risk Token Analysis (Structural Keywords)
        // These tokens (UNION, DROP) are extremely rare in legitimate user input.
        foreach (var token in HighRiskTokens)
        {
            if (normalizedInput.Contains(token.AsSpan(), StringComparison.Ordinal))
            {
                return CriticalThreat;
            }
        }

        return Safe;
    }
}