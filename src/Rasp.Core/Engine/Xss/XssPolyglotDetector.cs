using System.Buffers;

namespace Rasp.Core.Engine.Xss;

internal static class XssPolyglotDetector
{
    // Signatures known to break multiple contexts simultaneously
    private static readonly SearchValues<string> PolyglotSignatures = SearchValues.Create(
        [
            "\"><script>", "'><script>", "<svg/onload=", "<svg onload=",
            "';alert(", "\";alert(", "<img src=x onerror=", "javascript:alert",
            "-->", "--!>"
        ],
        StringComparison.OrdinalIgnoreCase);

    public static double CalculatePolyglotScore(ReadOnlySpan<char> payload)
    {
        double score = 0.0;

        if (payload.IndexOfAny(PolyglotSignatures) >= 0)
        {
            return 1.0;
        }

        int contexts = CountPotentialContexts(payload);

        if (contexts >= 2) score += 0.8;

        return Math.Min(score, 1.0);
    }

    private static int CountPotentialContexts(ReadOnlySpan<char> payload)
    {
        int contexts = 0;

        int ltIndex = payload.IndexOf('<');
        while (ltIndex >= 0 && ltIndex < payload.Length - 1)
        {
            char next = payload[ltIndex + 1];
            if (char.IsLetter(next) || next == '/' || next == '!' || next == '?')
            {
                contexts++;
                break;
            }

            var nextSlice = payload.Slice(ltIndex + 1);
            int nextLt = nextSlice.IndexOf('<');
            if (nextLt == -1) break;
            ltIndex += nextLt + 1;
        }

        int quoteIndex = payload.IndexOfAny('"', '\'');
        if (quoteIndex >= 0 && quoteIndex < payload.Length - 1)
        {
            var afterQuote = payload.Slice(quoteIndex + 1);

            int i = 0;
            while (i < afterQuote.Length && char.IsWhiteSpace(afterQuote[i])) i++;

            if (i < afterQuote.Length)
            {
                var relevant = afterQuote.Slice(i);
                if (relevant.StartsWith(">".AsSpan()) ||
                    relevant.StartsWith("on".AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    contexts++;
                }
            }
        }

        if (payload.Contains('(') && payload.Contains(')'))
        {
            if (ContainsFunctionCall(payload, "alert") ||
                ContainsFunctionCall(payload, "eval") ||
                ContainsFunctionCall(payload, "confirm") ||
                ContainsFunctionCall(payload, "prompt"))
            {
                contexts++;
            }
        }

        return contexts;
    }

    private static bool ContainsFunctionCall(ReadOnlySpan<char> payload, string functionName)
    {
        int idx = payload.IndexOf(functionName.AsSpan(), StringComparison.OrdinalIgnoreCase);

        while (idx >= 0)
        {
            var afterFn = payload.Slice(idx + functionName.Length);
            int i = 0;

            while (i < afterFn.Length)
            {
                char c = afterFn[i];

                if (char.IsWhiteSpace(c) || c < 32)
                {
                    i++;
                    continue;
                }

                if (c == '/' && i + 1 < afterFn.Length && afterFn[i + 1] == '*')
                {
                    int endComment = afterFn.Slice(i + 2).IndexOf("*/".AsSpan());
                    if (endComment >= 0)
                    {
                        i += 2 + endComment + 2;
                        continue;
                    }
                    else
                    {
                        i = afterFn.Length;
                        break;
                    }
                }

                if (c == '\\')
                {
                    if (i + 5 < afterFn.Length && afterFn[i + 1] == 'u')
                    {
                        i += 6;
                        continue;
                    }

                    if (i + 3 < afterFn.Length && afterFn[i + 1] == 'x')
                    {
                        i += 4;
                        continue;
                    }
                }

                break;
            }

            if (i < afterFn.Length && afterFn[i] == '(')
            {
                return true;
            }

            var nextSlice = payload.Slice(idx + 1);
            int nextIdx = nextSlice.IndexOf(functionName.AsSpan(), StringComparison.OrdinalIgnoreCase);
            if (nextIdx == -1) break;
            idx += nextIdx + 1;
        }

        return false;
    }
}