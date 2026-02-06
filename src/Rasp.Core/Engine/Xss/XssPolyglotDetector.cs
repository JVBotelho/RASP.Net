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

        // 1. Direct Signature Match (SIMD)
        // Se bater aqui, é ataque confirmado.
        if (payload.IndexOfAny(PolyglotSignatures) >= 0)
        {
            return 1.0; // Critical instantâneo
        }

        // 2. Context Diversity Heuristic (Zero-Alloc)
        // Verifica se o payload quebra múltiplos contextos ESTRUTURALMENTE.
        // Evita falsos positivos em textos como "User <3 Code".
        int contexts = CountPotentialContexts(payload);
        
        // Se quebrou 2 ou mais contextos (ex: HTML + Atributo), é altamente suspeito
        if (contexts >= 2) score += 0.8;

        return Math.Min(score, 1.0);
    }

    private static int CountPotentialContexts(ReadOnlySpan<char> payload)
    {
        int contexts = 0;

        // A. HTML Injection Context
        // Só conta se encontrar '<' seguido de:
        // - Letra (ex: <s, <a)
        // - '/' (fechamento de tag)
        // - '!' (comentário ou DOCTYPE)
        // - '?' (XML processing instruction)
        int ltIndex = payload.IndexOf('<');
        while (ltIndex >= 0 && ltIndex < payload.Length - 1)
        {
            char next = payload[ltIndex + 1];
            if (char.IsLetter(next) || next == '/' || next == '!' || next == '?')
            {
                contexts++;
                break; // Achou um, não precisa contar mais
            }
            
            // Busca próximo '<'
            var nextSlice = payload.Slice(ltIndex + 1);
            int nextLt = nextSlice.IndexOf('<');
            if (nextLt == -1) break;
            ltIndex += nextLt + 1;
        }

        // B. Attribute Injection Context
        // Procura por aspas seguidas de fechamento de tag (>) ou eventos (on...)
        // Ex: "><  ou  " on...=
        // Isso evita flagrar aspas em texto comum.
        int quoteIndex = payload.IndexOfAny('"', '\'');
        if (quoteIndex >= 0 && quoteIndex < payload.Length - 1)
        {
            var afterQuote = payload.Slice(quoteIndex + 1);
            
            // Pula espaços
            int i = 0;
            while (i < afterQuote.Length && char.IsWhiteSpace(afterQuote[i])) i++;
            
            if (i < afterQuote.Length)
            {
                var relevant = afterQuote.Slice(i);
                if (relevant.StartsWith(">".AsSpan()) || relevant.StartsWith("on".AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    contexts++;
                }
            }
        }

        // C. JS Context Breakout
        // Parenteses + palavras chave de execução
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
            // Verifica o que vem depois do nome da função
            var afterFn = payload.Slice(idx + functionName.Length);
            
            // Pula espaços
            int i = 0;
            while (i < afterFn.Length && char.IsWhiteSpace(afterFn[i])) i++;

            // Deve ser seguido IMEDIATAMENTE por '('
            if (i < afterFn.Length && afterFn[i] == '(')
            {
                return true;
            }

            // Busca próxima ocorrência
            var nextSlice = payload.Slice(idx + 1);
            int nextIdx = nextSlice.IndexOf(functionName.AsSpan(), StringComparison.OrdinalIgnoreCase);
            if (nextIdx == -1) break;
            idx += nextIdx + 1;
        }
        return false;
    }
}