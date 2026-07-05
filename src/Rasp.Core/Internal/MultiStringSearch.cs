using System.Buffers;

namespace Rasp.Core.Internal;

// SearchValues<string> (SIMD-accelerated multi-substring search) only exists from .NET 9
// onward - net8.0 needs a manual fallback with matching semantics (leftmost index, same
// StringComparison) so every call site can share one code path across both TFMs. See
// docs/ADR/008-nuget-packaging.md.
internal readonly struct MultiStringSearch
{
#if NET9_0_OR_GREATER
    private readonly SearchValues<string> _values;

    private MultiStringSearch(SearchValues<string> values) => _values = values;

    public static MultiStringSearch Create(string[] values, StringComparison comparison) =>
        new(SearchValues.Create(values, comparison));

    public bool ContainsAny(ReadOnlySpan<char> span) => span.ContainsAny(_values);

    public int IndexOfAny(ReadOnlySpan<char> span) => span.IndexOfAny(_values);
#else
    private readonly string[] _values;
    private readonly StringComparison _comparison;

    // First character of every pattern (case-folded when the comparison is ignore-case),
    // as a SearchValues<char> - that overload IS vectorized on net8.0, unlike
    // SearchValues<string>. Used to skip straight to positions that could possibly start a
    // match instead of running the O(patterns) StartsWith check at every single index.
    private readonly SearchValues<char> _firstChars;

    private MultiStringSearch(string[] values, StringComparison comparison, SearchValues<char> firstChars)
    {
        _values = values;
        _comparison = comparison;
        _firstChars = firstChars;
    }

    public static MultiStringSearch Create(string[] values, StringComparison comparison) =>
        new(values, comparison, SearchValues.Create(BuildFirstChars(values, comparison)));

    private static char[] BuildFirstChars(string[] values, StringComparison comparison)
    {
        bool ignoreCase = comparison is StringComparison.OrdinalIgnoreCase
            or StringComparison.InvariantCultureIgnoreCase
            or StringComparison.CurrentCultureIgnoreCase;

        var firstChars = new List<char>(values.Length * (ignoreCase ? 2 : 1));

        foreach (var value in values)
        {
            if (value.Length == 0) continue;

            char c = value[0];

            if (ignoreCase)
            {
                // ASCII-only patterns (HTML tags, SQL keywords) - invariant casing matches
                // ordinal casing for the characters actually in use here.
                firstChars.Add(char.ToUpperInvariant(c));
                firstChars.Add(char.ToLowerInvariant(c));
            }
            else
            {
                firstChars.Add(c);
            }
        }

        return [.. firstChars];
    }

    public bool ContainsAny(ReadOnlySpan<char> span) => IndexOfAny(span) >= 0;

    public int IndexOfAny(ReadOnlySpan<char> span)
    {
        int offset = 0;

        while (offset < span.Length)
        {
            int candidate = span.Slice(offset).IndexOfAny(_firstChars);
            if (candidate < 0) return -1;

            int absolute = offset + candidate;
            var remaining = span.Slice(absolute);

            foreach (var value in _values)
            {
                if (remaining.StartsWith(value.AsSpan(), _comparison))
                {
                    return absolute;
                }
            }

            offset = absolute + 1;
        }

        return -1;
    }
#endif
}
