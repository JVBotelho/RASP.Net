using System.Buffers;
using Microsoft.Extensions.Logging;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine.Sql;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

public class SqlInjectionDetectionEngine(ILogger<SqlInjectionDetectionEngine> logger) : IDetectionEngine
{
    private static readonly SearchValues<char> DangerousChars = 
        SearchValues.Create("'-;/*");

    private const int MaxStackAllocSize = 1024; 
    private const int MaxAnalysisLength = 4096; 

    // FIX 1: Renomeado de Analyze para Inspect para satisfazer a Interface
    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload)) 
            return DetectionResult.Safe(); //

        var inputSpan = payload.AsSpan();

        // Fast Path (SIMD)
        if (!inputSpan.ContainsAny(DangerousChars))
        {
            return DetectionResult.Safe();
        }

        // DoS Protection
        if (inputSpan.Length > MaxAnalysisLength)
        {
            inputSpan = inputSpan.Slice(0, MaxAnalysisLength);
        }

        char[]? rentedBuffer = null;
        Span<char> normalizedBuffer = inputSpan.Length <= MaxStackAllocSize
            ? stackalloc char[inputSpan.Length]
            : (rentedBuffer = ArrayPool<char>.Shared.Rent(inputSpan.Length));

        try
        {
            int written = SqlNormalizer.Normalize(inputSpan, normalizedBuffer);
            var searchSpace = normalizedBuffer.Slice(0, written);

            double score = SqlHeuristics.CalculateScore(searchSpace);

            if (score >= 1.0)
            {
                logger.LogWarning("⚔️ RASP Blocked SQLi! Score: {Score} Context: {Context}", score, context);
                
                // FIX 2: Usando o Factory Method estático que resolve os erros de inicialização
                return DetectionResult.Threat(
                    threatType: "SQL Injection",
                    description: $"SQL Injection Patterns Detected (Score: {score})",
                    severity: ThreatSeverity.High,
                    confidence: 1.0,
                    matchedPattern: "HeuristicScore"
                );
            }

            return DetectionResult.Safe();
        }
        finally
        {
            if (rentedBuffer != null)
            {
                ArrayPool<char>.Shared.Return(rentedBuffer);
            }
        }
    }
}