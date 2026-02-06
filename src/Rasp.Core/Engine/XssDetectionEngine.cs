using System.Buffers;
using System.Runtime.CompilerServices;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine.Xss;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

/// <summary>
/// High-performance XSS Analysis Service.
/// Implements Unsafe Pointer Arithmetic for zero-overhead decoding.
/// </summary>
public sealed class XssDetectionEngine : IDetectionEngine
{
    private static readonly SearchValues<char> SafeSyntax =
        SearchValues.Create("<>&\"'\\%:");

    private static readonly SearchValues<string> KillSwitchPatterns = SearchValues.Create(
        [
            "<script", "javascript:", "vbscript:", "data:text", "view-source:",
            "feed:", "<meta", "<iframe", "<object", "<embed", "<applet", "<style", "<template", "<noscript"
        ],
        StringComparison.OrdinalIgnoreCase);

    private static readonly SearchValues<char> DecodeTriggers =
        SearchValues.Create("&%\\");

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload)) return DetectionResult.Safe();
        if (payload.Length > 8192) return DetectionResult.Threat("DoS", "Payload limit exceeded", ThreatSeverity.High);

        return Inspect(payload.AsSpan(), context);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty) return DetectionResult.Safe();
        if (payload.Length > 8192) return DetectionResult.Threat("DoS", "Payload limit exceeded", ThreatSeverity.High);

        if (!payload.ContainsAny(SafeSyntax)) return DetectionResult.Safe();

        if (payload.ContainsAny(KillSwitchPatterns))
            return DetectionResult.Threat("XSS", "Signature Match (Raw)", ThreatSeverity.Critical);

        char[]? pooledObj = null;
        Span<char> buffer = payload.Length <= 1024
            ? stackalloc char[1024]
            : (pooledObj = ArrayPool<char>.Shared.Rent(payload.Length)).AsSpan(0, payload.Length);

        try
        {
            int effectiveLength = CanonicalizeInPlace(payload, buffer);
            var cleanPayload = buffer.Slice(0, effectiveLength);

            if (cleanPayload.ContainsAny(KillSwitchPatterns))
                return DetectionResult.Threat("XSS", "Signature Match (Obfuscated)", ThreatSeverity.Critical);

            if (XssPolyglotDetector.CalculatePolyglotScore(cleanPayload) >= 1.0)
                return DetectionResult.Threat("XSS", "Polyglot Context Breakout", ThreatSeverity.Critical);

            if (XssHeuristics.ScorePatterns(cleanPayload) >= 1.0)
                return DetectionResult.Threat("XSS", "Heuristic Structure Match", ThreatSeverity.High);

            return DetectionResult.Safe();
        }
        finally
        {
            if (pooledObj is not null) ArrayPool<char>.Shared.Return(pooledObj);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int CanonicalizeInPlace(ReadOnlySpan<char> input, Span<char> buffer)
    {
        int len = input.Length;
        input.CopyTo(buffer);

        bool mutated = true;
        int passes = 0;
        const int maxPasses = 5;

        while (mutated && passes < maxPasses)
        {
            mutated = false;
            int write = 0;

            for (int read = 0; read < len; read++)
            {
                char c = buffer[read];

                if (c < 32)
                {
                    mutated = true;
                    continue;
                }

                buffer[write++] = c;
            }

            if (write < len)
            {
                len = write;
            }

            var activeSlice = buffer.Slice(0, len);

            if (activeSlice.ContainsAny(DecodeTriggers))
            {
                int newLen = XssDecoder.PerformUnsafeDecodePass(activeSlice, out bool changed);
                if (changed)
                {
                    len = newLen;
                    mutated = true;
                }
            }
            passes++;
        }
        return len;
    }
}