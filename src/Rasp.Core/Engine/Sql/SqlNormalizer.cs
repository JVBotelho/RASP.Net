using System;
using System.Buffers;

namespace Rasp.Core.Engine.Sql;

internal static class SqlNormalizer
{
    // Define o que é "espaço em branco" para nós (Tab, CR, LF, etc)
    private static readonly SearchValues<char> WhitespaceChars = 
        SearchValues.Create(" \t\n\r\f\v");

    /// <summary>
    /// Normaliza o input para um buffer de saída (Stack).
    /// ToLower + Whitespace collapse em uma única passada.
    /// </summary>
    public static int Normalize(ReadOnlySpan<char> input, Span<char> output)
    {
        int outIdx = 0;
        bool lastWasSpace = false;

        for (int i = 0; i < input.Length; i++)
        {
            // Proteção contra buffer overflow (caso edge case)
            if (outIdx >= output.Length) break;

            char c = input[i];

            // 1. Tratamento de Espaços
            // Se for um char de espaço (tab, enter), normaliza para ' '
            if (WhitespaceChars.Contains(c))
            {
                if (!lastWasSpace)
                {
                    output[outIdx++] = ' ';
                    lastWasSpace = true;
                }
                continue;
            }

            // 2. ToLower (Otimizado para ASCII)
            // 'A' (65) até 'Z' (90). Adiciona 32 para virar minúscula.
            // Para unicode complexo, isso falha, mas para SQLi keywords (inglês) é perfeito e rápido.
            if (c >= 'A' && c <= 'Z')
            {
                c = (char)(c | 0x20); // Bitwise hack para lowercase
            }

            output[outIdx++] = c;
            lastWasSpace = false;
        }

        return outIdx; // Retorna quantos caracteres foram escritos
    }
}