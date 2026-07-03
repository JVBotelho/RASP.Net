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
/// <para>
/// This is signature/heuristic-based, not a formal SQL parser - it accepts documented
/// residual gaps rather than a naive fix that would false-positive on legitimate ORM
/// output. Two known gaps: (1) tautologies via inequality with distinct constants or
/// <c>BETWEEN</c> (e.g. <c>OR 5&gt;1</c>, <c>OR 1 BETWEEN 1 AND 9</c>) are not detected -
/// only same-operand equality (<c>OR X=X</c>) is, to avoid full numeric constant folding;
/// (2) a stacked <c>;SELECT</c> for blind exfiltration is not flagged, because EF Core's
/// own SaveChanges() batching legitimately appends INSERT/UPDATE/DELETE/SELECT statements
/// and there is no reliable way to distinguish the two by verb alone (see
/// <see cref="HasDangerousStackedQuery"/>).
/// </para>
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

    // Generic "X = X" tautology detection, rather than an enumerated literal list: an
    // enumeration of exact strings (`or 1=1`, `or 'a'='a'`, ...) is trivially bypassed by any
    // operand pair not on the list (`or 2=2`, `or 'x'='x'`, `or 5=5`, ...). This scans for
    // "or " followed by an operand, `=`, and a second operand, and flags it whenever both
    // operands are textually identical - which is exactly what makes the comparison always
    // true regardless of which literal an attacker picks. Deliberately scoped to `=` with
    // identical operands (not full constant folding of `>`/`<`/`BETWEEN` with different
    // literals, e.g. `or 5>1`) to stay zero-alloc and avoid false-positive risk from
    // evaluating arbitrary numeric comparisons; that remains a documented residual gap.
    private static bool HasTautology(ReadOnlySpan<char> normalized)
    {
        int offset = 0;
        while (true)
        {
            int orIndex = normalized.Slice(offset).IndexOf("or ", StringComparison.Ordinal);
            if (orIndex < 0) break;

            int absoluteOrIndex = offset + orIndex;

            // Word boundary before "or " - otherwise "color " or "author " would false-match.
            bool hasWordBoundary = absoluteOrIndex == 0 || !IsIdentifierChar(normalized[absoluteOrIndex - 1]);
            if (!hasWordBoundary)
            {
                offset = absoluteOrIndex + 3;
                continue;
            }

            var rest = normalized.Slice(absoluteOrIndex + 3);
            if (TryExtractOperand(rest, out var lhs, out int lhsConsumed))
            {
                var afterLhs = rest.Slice(lhsConsumed).TrimStart();
                if (afterLhs.Length > 0 && afterLhs[0] == '=')
                {
                    var afterEq = afterLhs.Slice(1).TrimStart();
                    if (TryExtractOperand(afterEq, out var rhs, out _) && lhs.SequenceEqual(rhs))
                    {
                        return true;
                    }
                }
            }

            offset = absoluteOrIndex + 3;
        }

        return false;
    }

    private static bool IsIdentifierChar(char c) => char.IsLetterOrDigit(c) || c == '_';

    // Extracts a single comparison operand starting at the front of `span`: either a
    // quote-delimited string literal (quotes included, so 'a' != a) or a bare run of
    // identifier/number characters. Returns false if `span` doesn't start with an operand.
    private static bool TryExtractOperand(ReadOnlySpan<char> span, out ReadOnlySpan<char> operand, out int consumed)
    {
        operand = default;
        consumed = 0;
        if (span.IsEmpty) return false;

        char quote = span[0];
        if (quote == '\'' || quote == '"')
        {
            int closingIndex = span.Slice(1).IndexOf(quote);
            if (closingIndex < 0) return false;

            consumed = closingIndex + 2;
            operand = span.Slice(0, consumed);
            return true;
        }

        int length = 0;
        while (length < span.Length && (IsIdentifierChar(span[length]) || span[length] == '.'))
        {
            length++;
        }

        if (length == 0) return false;

        consumed = length;
        operand = span.Slice(0, length);
        return true;
    }

    private static readonly string[] StackedQueryVerbs =
    [
        "drop", "alter", "truncate", "exec", "xp_", "waitfor",
        "grant", "revoke", "shutdown", "merge", "create"
    ];

    private static bool HasDangerousStackedQuery(ReadOnlySpan<char> normalized)
    {
        // EF Core batches using semicolons (e.g. `...;insertinto...`) - and EF's own
        // SaveChanges() batching legitimately generates stacked INSERT/UPDATE/DELETE/SELECT
        // (e.g. multiple tracked entities in one round trip, or a trailing SELECT reading
        // back a generated identity column). Those four verbs are deliberately NOT in this
        // list even though an attacker could stack them too (see
        // Inspect_ShouldNotFlag_NormalEfBatching) - flagging them would false-positive on
        // routine EF usage. GRANT/REVOKE/SHUTDOWN/MERGE/CREATE, by contrast, are never
        // something EF Core's own query generator produces, so adding them closes real gaps
        // (privilege escalation, DoS, rogue object creation) without that tradeoff. Blind
        // exfiltration via an attacker-appended `;SELECT` remains a known, accepted residual
        // gap for exactly this reason - it can't be distinguished from EF's own trailing
        // SELECT by verb alone.
        int offset = 0;
        while (true)
        {
            int index = normalized.Slice(offset).IndexOf(';');
            if (index < 0) break;

            int absoluteIndex = offset + index;
            if (absoluteIndex + 1 < normalized.Length)
            {
                var afterSemicolon = normalized.Slice(absoluteIndex + 1).TrimStart();
                foreach (var verb in StackedQueryVerbs)
                {
                    if (afterSemicolon.StartsWith(verb, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }

            offset = absoluteIndex + 1;
        }

        return false;
    }
}
