using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
// ReSharper disable MergeIntoPattern

namespace Rasp.Core.Engine.Xss;

/// <summary>
/// Uses AggressiveInlining to ensure JIT merges this into the Hot Path.
/// </summary>
internal static class XssDecoder
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int PerformUnsafeDecodePass(Span<char> span, out bool changed)
    {
        int read = 0;
        int write = 0;
        int len = span.Length;
        changed = false;

        int complexityBudget = 200;

        ref char ptr = ref MemoryMarshal.GetReference(span);

        while (read < len)
        {
            char c = Unsafe.Add(ref ptr, read);

            if (c == '%' && read + 2 < len)
            {
                if (complexityBudget > 0 && TryFastHexDecode(Unsafe.Add(ref ptr, read + 1), Unsafe.Add(ref ptr, read + 2), out char decoded))
                {
                    Unsafe.Add(ref ptr, write++) = decoded;
                    read += 3;
                    changed = true;
                    complexityBudget--;
                    continue;
                }
            }
            else if (c == '\\')
            {
                if (complexityBudget > 0)
                {
                    if (read + 5 < len && Unsafe.Add(ref ptr, read + 1) == 'u')
                    {
                        if (TryFastHexDecode4(
                            Unsafe.Add(ref ptr, read + 2), Unsafe.Add(ref ptr, read + 3),
                            Unsafe.Add(ref ptr, read + 4), Unsafe.Add(ref ptr, read + 5),
                            out char decoded))
                        {
                            Unsafe.Add(ref ptr, write++) = decoded;
                            read += 6;
                            changed = true;
                            complexityBudget--;
                            continue;
                        }
                    }
                    else if (read + 3 < len && Unsafe.Add(ref ptr, read + 1) == 'x')
                    {
                        if (TryFastHexDecode(Unsafe.Add(ref ptr, read + 2), Unsafe.Add(ref ptr, read + 3), out char decoded))
                        {
                            Unsafe.Add(ref ptr, write++) = decoded;
                            read += 4;
                            changed = true;
                            complexityBudget--;
                            continue;
                        }
                    }
                }
            }
            else if (c == '&')
            {
                int remaining = len - read;
                if (complexityBudget > 0 && remaining > 3)
                {
                    if (Unsafe.Add(ref ptr, read + 1) == 'l' && Unsafe.Add(ref ptr, read + 2) == 't' && Unsafe.Add(ref ptr, read + 3) == ';')
                    {
                        Unsafe.Add(ref ptr, write++) = '<'; read += 4; changed = true; complexityBudget--; continue;
                    }
                    if (Unsafe.Add(ref ptr, read + 1) == 'g' && Unsafe.Add(ref ptr, read + 2) == 't' && Unsafe.Add(ref ptr, read + 3) == ';')
                    {
                        Unsafe.Add(ref ptr, write++) = '>'; read += 4; changed = true; complexityBudget--; continue;
                    }
                    if (Unsafe.Add(ref ptr, read + 1) == '#')
                    {
                        bool isHex = (remaining > 4 && (Unsafe.Add(ref ptr, read + 2) == 'x' || Unsafe.Add(ref ptr, read + 2) == 'X'));
                        int startDigit = isHex ? 3 : 2;

                        if (TryDecodeNumericEntity(ref ptr, read, remaining, startDigit, isHex, out char entityChar, out int consumed))
                        {
                            Unsafe.Add(ref ptr, write++) = entityChar;
                            read += consumed;
                            changed = true;
                            complexityBudget--;
                            continue;
                        }
                    }
                    if (remaining > 4)
                    {
                        if (Unsafe.Add(ref ptr, read + 1) == 'a' && Unsafe.Add(ref ptr, read + 2) == 'm' && Unsafe.Add(ref ptr, read + 3) == 'p' && Unsafe.Add(ref ptr, read + 4) == ';')
                        {
                            Unsafe.Add(ref ptr, write++) = '&'; read += 5; changed = true; complexityBudget--; continue;
                        }
                    }
                    if (remaining > 5)
                    {
                        char n1 = Unsafe.Add(ref ptr, read + 1);
                        if (n1 == 'q' && Unsafe.Add(ref ptr, read + 2) == 'u' && Unsafe.Add(ref ptr, read + 3) == 'o' && Unsafe.Add(ref ptr, read + 4) == 't' && Unsafe.Add(ref ptr, read + 5) == ';')
                        {
                            Unsafe.Add(ref ptr, write++) = '"'; read += 6; changed = true; complexityBudget--; continue;
                        }
                        if (n1 == 'a' && Unsafe.Add(ref ptr, read + 2) == 'p' && Unsafe.Add(ref ptr, read + 3) == 'o' && Unsafe.Add(ref ptr, read + 4) == 's' && Unsafe.Add(ref ptr, read + 5) == ';')
                        {
                            Unsafe.Add(ref ptr, write++) = '\''; read += 6; changed = true; complexityBudget--; continue;
                        }
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

        int maxLoop = Math.Min(maxLen, 10);

        for (; i < maxLoop; i++)
        {
            char d = Unsafe.Add(ref basePtr, currentRead + i);
            if (d == ';')
            {
                if (i == offset || val == 0) return false;
                result = (char)val;
                consumed = i + 1;
                return true;
            }

            int digit = -1;
            if (d >= '0' && d <= '9') digit = d - '0';
            else if (isHex)
            {
                digit = d switch
                {
                    >= 'a' and <= 'f' => d - 'a' + 10,
                    >= 'A' and <= 'F' => d - 'A' + 10,
                    _ => digit
                };
            }

            if (digit == -1) return false;

            if (isHex) val = (val << 4) | digit;
            else val = val * 10 + digit;

            if (val > 0xFFFF) return false;
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
        return val switch
        {
            >= '0' and <= '9' => val - '0',
            >= 'A' and <= 'F' => val - ('A' - 10),
            >= 'a' and <= 'f' => val - ('a' - 10),
            _ => -1
        };
    }
}