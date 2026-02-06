using System.Buffers;
using System.Runtime.CompilerServices;

namespace Rasp.Core.Engine.Xss;

/// <summary>
/// Elite Zero-Allocation Decoder.
/// Handles: HTML Entities, URL Encoding, JS Unicode/Hex Escapes.
/// Implements Recursive Canonicalization (Anti-Evasion).
/// </summary>
internal static class XssDecoder
{
    private const int MaxRecursionDepth = 5; // Evita DoS por loops de encoding
    private const int MaxEntityLength = 32;

    // Gatilhos para decodificação: &, %, \
    private static readonly SearchValues<char> EncodedTriggers = 
        SearchValues.Create("&%\\");

    /// <summary>
    /// Canonicalizes the input by recursively decoding layers of obfuscation.
    /// Ex: "%253Cscript" -> "%3Cscript" -> "<script"
    /// </summary>
    public static int Canonicalize(ReadOnlySpan<char> input, Span<char> output)
    {
        // 1. Cópia inicial para o buffer de trabalho
        if (input.Length > output.Length) return 0; // Buffer overflow protection
        input.CopyTo(output);
        int currentLength = input.Length;

        // 2. Loop de Decodificação Recursiva (Peeling the Onion)
        for (int depth = 0; depth < MaxRecursionDepth; depth++)
        {
            var currentSpan = output.Slice(0, currentLength);
            
            // Fast Check: Se não tem caracteres codificados, paramos.
            if (!currentSpan.ContainsAny(EncodedTriggers))
            {
                break;
            }

            // Realiza uma passada de decodificação
            bool changed = false;
            int newLength = DecodePass(currentSpan, output, out changed);
            
            if (!changed || newLength == currentLength) break; // Estabilizou
            
            currentLength = newLength;
        }

        return currentLength;
    }

    // Realiza uma passada de decodificação unificada (URL + HTML + JS Escapes)
    private static int DecodePass(ReadOnlySpan<char> input, Span<char> output, out bool changed)
    {
        int read = 0;
        int write = 0;
        changed = false;
        int len = input.Length;

        // Buffer temporário na stack para evitar corrupção (in-place decode é arriscado sem shift correto)
        // Limitamos stackalloc para segurança. Se for maior, não decodifica recursivamente (fallback seguro).
        if (len > 4096) 
        {
            input.CopyTo(output);
            return len;
        }

        Span<char> temp = stackalloc char[len];

        while (read < len)
        {
            char c = input[read];

            // 1. URL Decode (%XX)
            if (c == '%' && read + 2 < len)
            {
                if (TryDecodeHex(input.Slice(read + 1, 2), out char decodedChar))
                {
                    temp[write++] = decodedChar;
                    read += 3;
                    changed = true;
                    continue;
                }
            }

            // 2. JS Escapes (\uXXXX or \xXX)
            if (c == '\\')
            {
                // \uXXXX
                if (read + 5 < len && input[read + 1] == 'u')
                {
                    if (TryDecodeHex(input.Slice(read + 2, 4), out char decodedChar))
                    {
                        temp[write++] = decodedChar;
                        read += 6;
                        changed = true;
                        continue;
                    }
                }
                // \xXX
                else if (read + 3 < len && input[read + 1] == 'x')
                {
                    if (TryDecodeHex(input.Slice(read + 2, 2), out char decodedChar))
                    {
                        temp[write++] = decodedChar;
                        read += 4;
                        changed = true;
                        continue;
                    }
                }
            }

            // 3. HTML Entities (&lt;)
            if (c == '&')
            {
                int end = FindEntityEnd(input, read);
                if (end != -1)
                {
                    var entity = input.Slice(read + 1, end - read - 1); // Remove & e ;
                    char entityChar = DecodeEntity(entity);

                    if (entityChar != '\0')
                    {
                        temp[write++] = entityChar;
                        read = end + 1;
                        changed = true;
                        continue;
                    }
                }
            }

            // Char normal
            temp[write++] = input[read++];
        }

        // Copia de volta para o output buffer
        temp.Slice(0, write).CopyTo(output);
        return write;
    }

    private static int FindEntityEnd(ReadOnlySpan<char> input, int start)
    {
        int max = Math.Min(start + MaxEntityLength, input.Length);
        for (int i = start + 1; i < max; i++)
        {
            char c = input[i];
            if (c == ';') return i;
            if (c == '&' || char.IsWhiteSpace(c)) return -1;
        }
        return -1;
    }

    private static char DecodeEntity(ReadOnlySpan<char> entity)
    {
        if (entity.IsEmpty) return '\0';

        if (entity[0] != '#') return DecodeNamedEntity(entity);
        var num = entity.Slice(1); // Remove #
        if (num.IsEmpty) return '\0';

        bool isHex = num.Length > 1 && (num[0] == 'x' || num[0] == 'X');
        return isHex ? ParseHex(num.Slice(1)) : ParseDecimal(num);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryDecodeHex(ReadOnlySpan<char> hex, out char result)
    {
        result = '\0';
        int val = 0;
        foreach (char c in hex)
        {
            int digit = -1;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            
            if (digit == -1) return false;

            val = (val << 4) | digit;
        }
        result = (char)val;
        return true;
    }

    private static char ParseDecimal(ReadOnlySpan<char> num)
    {
        int result = 0;
        foreach (char c in num)
        {
            if (c is < '0' or > '9') return '\0';
            
            // FIX: Overflow check ANTES da operação
            if (result > 6553) return '\0'; // 65535 / 10 ≈ 6553

            result = result * 10 + (c - '0');
            
            if (result > 0xFFFF) return '\0';
        }
        return (char)result;
    }

    private static char ParseHex(ReadOnlySpan<char> num)
    {
        int result = 0;
        foreach (char c in num)
        {
            int val = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'a' and <= 'f' => c - 'a' + 10,
                >= 'A' and <= 'F' => c - 'A' + 10,
                _ => -1
            };
            if (val == -1) return '\0';

            // FIX: Overflow check ANTES da operação
            if (result > 4095) return '\0'; // 0xFFFF / 16 = 4095

            result = result * 16 + val;
            
            if (result > 0xFFFF) return '\0';
        }
        return (char)result;
    }

    private static char DecodeNamedEntity(ReadOnlySpan<char> name)
    {
        // Switch expression com hash otimizado pelo compilador
        return name switch
        {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            "tab" => '\t',
            "newline" => '\n',
            "colon" => ':',
            _ => '\0'
        };
    }
}