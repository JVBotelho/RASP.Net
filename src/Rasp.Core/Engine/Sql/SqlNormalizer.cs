using System.Runtime.CompilerServices;

namespace Rasp.Core.Engine.Sql;

public static class SqlNormalizer
{
    /// <summary>
    /// Normalizes SQL input for inspection:
    /// 1. Converts ASCII 'A'-'Z' to 'a'-'z' (Zero-Alloc Bitwise).
    /// 2. Preserves Unicode characters (> 127) intact (no data corruption).
    /// 3. Collapses multiple spaces into a single space.
    /// 4. Stops processing if the output buffer is full.
    /// </summary>
    /// <param name="input">The raw SQL payload.</param>
    /// <param name="output">The buffer to write normalized characters to.</param>
    /// <returns>The number of characters written to the output.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int Normalize(ReadOnlySpan<char> input, Span<char> output)
    {
        int written = 0;
        int maxLen = output.Length;
        bool lastWasSpace = false;

        for (int i = 0; i < input.Length; i++)
        {
            if (written >= maxLen)
            {
                break; 
            }

            char c = input[i];

            if (!char.IsAscii(c)) 
            {
                output[written++] = c;
                lastWasSpace = false;
                continue;
            }

            // --- ASCII LOGIC ---
            
            // Collapse Whitespace (Tab, NewLine, Space)
            if (c <= ' ') 
            {
                if (!lastWasSpace)
                {
                    output[written++] = ' ';
                    lastWasSpace = true;
                }
                continue;
            }

            lastWasSpace = false;

            // Bitwise ToLower for A-Z only
            // (uint)(c - 'A') <= ('Z' - 'A') is an unsigned trick to check range in one op
            if ((uint)(c - 'A') <= ('Z' - 'A'))
            {
                output[written++] = (char)(c | 0x20);
            }
            else
            {
                output[written++] = c;
            }
        }

        return written;
    }
}