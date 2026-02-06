using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine.Xss;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

/// <summary>
/// High-performance XSS Analysis Service.
/// Implements Unsafe Pointer Arithmetic for zero-overhead decoding.
/// Pure Logic: No I/O, No Logging, No Side Effects.
/// </summary>
public sealed class XssDetectionEngine : IDetectionEngine
{
    // 🚀 STAGE 1: Syntax Filters (Bitmask/SIMD)
    private static readonly SearchValues<char> SafeSyntax = 
        SearchValues.Create("<>&\"'\\%");

    // 🚀 STAGE 2: Kill Switch Patterns (Assinaturas Óbvias)
    private static readonly SearchValues<string> KillSwitchPatterns = SearchValues.Create(
        [
            "<script", "javascript:", "vbscript:", "data:text", "view-source:", 
            "feed:", "<meta", "<iframe", "<object", "<embed", "<applet", "<style", "<template", "<noscript"
        ], 
        StringComparison.OrdinalIgnoreCase);

    // Triggers: Apenas caracteres que INICIAM uma sequência codificada.
    // Removido '+' (Middleware lida) e '#' (Só é especial após '&').
    private static readonly SearchValues<char> DecodeTriggers = 
        SearchValues.Create("&%\\"); 

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload)) return DetectionResult.Safe();
        // DoS Protection: Fail-closed without logging inside the hot path
        if (payload.Length > 8192) return DetectionResult.Threat("DoS", "Payload limit exceeded", ThreatSeverity.High);
        
        return Inspect(payload.AsSpan(), context);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty) return DetectionResult.Safe();
        if (payload.Length > 8192) return DetectionResult.Threat("DoS", "Payload limit exceeded", ThreatSeverity.High);

        // 1. Fast Path
        if (!payload.ContainsAny(SafeSyntax)) return DetectionResult.Safe();

        // 2. Kill Switch (Raw)
        if (payload.ContainsAny(KillSwitchPatterns))
             return DetectionResult.Threat("XSS", "Signature Match (Raw)", ThreatSeverity.Critical);

        // 3. Memory Management
        char[]? pooledObj = null;
        Span<char> buffer = payload.Length <= 1024 
            ? stackalloc char[1024] 
            : (pooledObj = ArrayPool<char>.Shared.Rent(payload.Length)).AsSpan(0, payload.Length);

        try 
        {
            // 4. Canonicalization (Peeling the Onion)
            int effectiveLength = CanonicalizeInPlace(payload, buffer);
            var cleanPayload = buffer.Slice(0, effectiveLength);

            // 5. Re-Scan (Obfuscated)
            if (cleanPayload.ContainsAny(KillSwitchPatterns))
                return DetectionResult.Threat("XSS", "Signature Match (Obfuscated)", ThreatSeverity.Critical);

            // 6. Polyglot & Heuristics
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
            var activeSlice = buffer.Slice(0, len);
            
            if (activeSlice.ContainsAny(DecodeTriggers))
            {
                int newLen = PerformUnsafeDecodePass(activeSlice, out bool changed);
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int PerformUnsafeDecodePass(Span<char> span, out bool changed)
    {
        int read = 0;
        int write = 0;
        int len = span.Length;
        changed = false;

        ref char ptr = ref MemoryMarshal.GetReference(span);

        while (read < len)
        {
            char c = Unsafe.Add(ref ptr, read);

            // 1. URL Decode (%XX)
            if (c == '%' && read + 2 < len)
            {
                if (TryFastHexDecode(Unsafe.Add(ref ptr, read+1), Unsafe.Add(ref ptr, read+2), out char decoded))
                {
                    Unsafe.Add(ref ptr, write++) = decoded;
                    read += 3;
                    changed = true;
                    continue;
                }
            }
            // 2. JS Escapes (\)
            else if (c == '\\')
            {
                // \uXXXX
                if (read + 5 < len && Unsafe.Add(ref ptr, read+1) == 'u')
                {
                      if (TryFastHexDecode4(
                          Unsafe.Add(ref ptr, read+2), Unsafe.Add(ref ptr, read+3),
                          Unsafe.Add(ref ptr, read+4), Unsafe.Add(ref ptr, read+5), 
                          out char decoded))
                      {
                          Unsafe.Add(ref ptr, write++) = decoded;
                          read += 6;
                          changed = true;
                          continue;
                      }
                }
                // \xXX
                else if (read + 3 < len && Unsafe.Add(ref ptr, read+1) == 'x')
                {
                    if (TryFastHexDecode(Unsafe.Add(ref ptr, read+2), Unsafe.Add(ref ptr, read+3), out char decoded))
                    {
                        Unsafe.Add(ref ptr, write++) = decoded;
                        read += 4;
                        changed = true;
                        continue;
                    }
                }
            }
            // 3. HTML Entities (&...) - Enhanced
            else if (c == '&')
            {
                int remaining = len - read;
                if (remaining > 3)
                {
                    // Named: &lt;
                    if (Unsafe.Add(ref ptr, read+1) == 'l' && Unsafe.Add(ref ptr, read+2) == 't' && Unsafe.Add(ref ptr, read+3) == ';') {
                        Unsafe.Add(ref ptr, write++) = '<'; read += 4; changed = true; continue;
                    }
                    // Named: &gt;
                    if (Unsafe.Add(ref ptr, read+1) == 'g' && Unsafe.Add(ref ptr, read+2) == 't' && Unsafe.Add(ref ptr, read+3) == ';') {
                        Unsafe.Add(ref ptr, write++) = '>'; read += 4; changed = true; continue;
                    }
                    // Numeric: &#...
                    if (Unsafe.Add(ref ptr, read+1) == '#')
                    {
                        // Check for Hex &#x...
                        bool isHex = (remaining > 4 && (Unsafe.Add(ref ptr, read+2) == 'x' || Unsafe.Add(ref ptr, read+2) == 'X'));
                        int startDigit = isHex ? 3 : 2;
                        
                        // Parse safely
                        if (TryDecodeNumericEntity(ref ptr, read, remaining, startDigit, isHex, out char entityChar, out int consumed))
                        {
                            Unsafe.Add(ref ptr, write++) = entityChar;
                            read += consumed;
                            changed = true;
                            continue;
                        }
                    }
                }
                // Named: &amp;
                if (remaining > 4)
                {
                      if (Unsafe.Add(ref ptr, read+1) == 'a' && Unsafe.Add(ref ptr, read+2) == 'm' && Unsafe.Add(ref ptr, read+3) == 'p' && Unsafe.Add(ref ptr, read+4) == ';') {
                        Unsafe.Add(ref ptr, write++) = '&'; read += 5; changed = true; continue;
                    }
                }
                // Named: &quot; and &apos; (Crucial for Attribute Breakout Detection)
                if (remaining > 5)
                {
                     char n1 = Unsafe.Add(ref ptr, read+1);
                     if (n1 == 'q' && Unsafe.Add(ref ptr, read+2) == 'u' && Unsafe.Add(ref ptr, read+3) == 'o' && Unsafe.Add(ref ptr, read+4) == 't' && Unsafe.Add(ref ptr, read+5) == ';') {
                        Unsafe.Add(ref ptr, write++) = '"'; read += 6; changed = true; continue;
                    }
                     if (n1 == 'a' && Unsafe.Add(ref ptr, read+2) == 'p' && Unsafe.Add(ref ptr, read+3) == 'o' && Unsafe.Add(ref ptr, read+4) == 's' && Unsafe.Add(ref ptr, read+5) == ';') {
                        Unsafe.Add(ref ptr, write++) = '\''; read += 6; changed = true; continue;
                    }
                }
            }

            Unsafe.Add(ref ptr, write++) = c;
            read++;
        }
        return write;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryDecodeNumericEntity(ref char basePtr, int currentRead, int maxLen, int offset, bool isHex, out char result, out int consumed)
    {
        result = '\0';
        consumed = 0;
        int val = 0;
        int i = offset;
        
        // Max entity length check (prevent excessive looping)
        int maxLoop = Math.Min(maxLen, 10); 

        for (; i < maxLoop; i++)
        {
            char d = Unsafe.Add(ref basePtr, currentRead + i);
            if (d == ';')
            {
                if (i == offset) return false; // Empty &#;
                result = (char)val;
                consumed = i + 1;
                return true;
            }

            int digit = -1;
            if (d >= '0' && d <= '9') digit = d - '0';
            else if (isHex)
            {
                if (d >= 'a' && d <= 'f') digit = d - 'a' + 10;
                else if (d >= 'A' && d <= 'F') digit = d - 'A' + 10;
            }

            if (digit == -1) return false; // Invalid char

            if (isHex) val = (val << 4) | digit;
            else val = val * 10 + digit;

            if (val > 0xFFFF) return false; // Overflow
        }
        return false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryFastHexDecode(char h1, char h2, out char result)
    {
        int v1 = GetHexVal(h1);
        int v2 = GetHexVal(h2);
        if ((v1 | v2) < 0) { result = '\0'; return false; }
        result = (char)((v1 << 4) | v2);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryFastHexDecode4(char h1, char h2, char h3, char h4, out char result)
    {
        int v1 = GetHexVal(h1); int v2 = GetHexVal(h2);
        int v3 = GetHexVal(h3); int v4 = GetHexVal(h4);
        if ((v1 | v2 | v3 | v4) < 0) { result = '\0'; return false; }
        result = (char)((v1 << 12) | (v2 << 8) | (v3 << 4) | v4);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetHexVal(char c)
    {
        int val = c;
        if (val >= '0' && val <= '9') return val - '0';
        if (val >= 'A' && val <= 'F') return val - ('A' - 10);
        if (val >= 'a' && val <= 'f') return val - ('a' - 10);
        return -1;
    }
}