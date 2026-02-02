using System;

namespace Rasp.Core.Engine.Sql;

internal static class SqlHeuristics
{
    // Lista de tokens perigosos. 
    // Em produção, isso viria de configuração, mas aqui hardcoded é mais rápido.
    private static readonly string[] HighRiskTokens = 
    [
        "union select", 
        "insert into", 
        "delete from", 
        "drop table", 
        "exec(", 
        "xp_cmdshell"
    ];

    private static readonly string[] MediumRiskTokens = 
    [
        " or ", // ' OR '
        " and ",
        "--", 
        "/*", 
        "@@version"
    ];

    public static double CalculateScore(ReadOnlySpan<char> normalizedInput)
    {
        double score = 0;

        // Análise de Tokens de Alto Risco (Peso 1.0 = Bloqueio Imediato)
        foreach (var token in HighRiskTokens)
        {
            // MemoryExtensions.Contains opera sobre Span sem alocar
            if (normalizedInput.Contains(token.AsSpan(), StringComparison.Ordinal))
            {
                return 1.0; // Fail fast
            }
        }

        // Análise de Tokens de Médio Risco (Peso 0.5)
        foreach (var token in MediumRiskTokens)
        {
            if (normalizedInput.Contains(token.AsSpan(), StringComparison.Ordinal))
            {
                score += 0.5;
            }
        }

        // Análise Estrutural: Aspas desbalanceadas
        // Ex: ' OR 1=1
        int quoteCount = 0;
        foreach (char c in normalizedInput)
        {
            if (c == '\'') quoteCount++;
        }

        if (quoteCount % 2 != 0)
        {
            score += 0.3;
        }

        return score;
    }
}