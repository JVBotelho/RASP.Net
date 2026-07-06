using System.Diagnostics.CodeAnalysis;
using Rasp.Core.Internal;

// ReSharper disable ReplaceSliceWithRangeIndexer

namespace Rasp.Core.Engine.Xss;

[SuppressMessage("Style", "IDE0057:Use range operator")]
internal static class XssHeuristics
{
    // High Risk Tags: Immediate execution probability.
    private static readonly MultiStringSearch ExecutionTags = MultiStringSearch.Create(
        ["<link"],
        StringComparison.OrdinalIgnoreCase);

    // Suspicious Tags: Context-dependent risk.
    private static readonly MultiStringSearch SuspiciousTags = MultiStringSearch.Create(
        ["<img", "<svg", "<video", "<audio", "<body", "<input", "<details", "<form"],
        StringComparison.OrdinalIgnoreCase);

    // Dangerous Protocols: Pseudo-protocols that execute code.
    private static readonly MultiStringSearch DangerousProtocols = MultiStringSearch.Create(
        ["data:image/svg+xml"],
        StringComparison.OrdinalIgnoreCase);

    // DOM Events: Optimized for SIMD Aho-Corasick search (NET 9+); manual fallback on net8.0.
    // Scans for all 14 patterns simultaneously.
    private static readonly MultiStringSearch DomEventsSearch = MultiStringSearch.Create(
        [
            "onload", "onerror", "onclick", "onmouseover", "onfocus",
            "onblur", "onchange", "onsubmit", "onkeydown", "onkeyup",
            "onmouseenter", "onmouseleave", "ontoggle", "onanimationstart"
        ],
        StringComparison.OrdinalIgnoreCase);

    public static double ScorePatterns(ReadOnlySpan<char> input)
    {
        if (ExecutionTags.ContainsAny(input))
        {
            return 1.0;
        }

        if (DangerousProtocols.ContainsAny(input))
        {
            return 1.0;
        }

        if (ScoreEventHandlers(input) >= 1.0)
        {
            return 1.0;
        }

        if (SuspiciousTags.ContainsAny(input))
        {
            return 0.5;
        }

        return 0.0;
    }

    private static double ScoreEventHandlers(ReadOnlySpan<char> input)
    {
        var remaining = input;

        while (true)
        {
            int idx = DomEventsSearch.IndexOfAny(remaining);

            if (idx < 0) break;

            var matchSlice = remaining.Slice(idx);

            int forwardCursor = 0;

            while (forwardCursor < matchSlice.Length && char.IsLetter(matchSlice[forwardCursor]))
            {
                forwardCursor++;
            }

            while (forwardCursor < matchSlice.Length && (char.IsWhiteSpace(matchSlice[forwardCursor]) || matchSlice[forwardCursor] < 32))
            {
                forwardCursor++;
            }

            if (forwardCursor < matchSlice.Length && matchSlice[forwardCursor] == '=')
            {
                return 1.0;
            }

            remaining = matchSlice.Slice(forwardCursor > 0 ? forwardCursor : 1);
        }

        return 0.0;
    }
}