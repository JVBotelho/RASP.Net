using System.Text.RegularExpressions;
using Rasp.Core.Abstractions;
using Rasp.Core.Enums;
using Rasp.Core.Models;

namespace Rasp.Core.Engine;

/// <summary>
/// A basic detection engine based on Regular Expressions.
/// NOTE: In a real-world scenario, this would be much more sophisticated.
/// For the PoC, we focus on blocking the most obvious SQLi patterns.
/// </summary>
public partial class RegexDetectionEngine : IDetectionEngine
{
    // Otimização: Source Generator para Regex (Zero-Allocation na inicialização)
    // Bloqueia: ' OR '1'='1 (e variações simples)
    [GeneratedRegex(@"(?i)'\s*OR\s*'\d+'\s*=\s*'\d+", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex BasicSqlInjectionPattern();

    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload))
        {
            return DetectionResult.Safe();
        }

        // 1. Check for Basic SQL Injection
        if (BasicSqlInjectionPattern().IsMatch(payload))
        {
            return DetectionResult.Threat(
                threatType: "SQL Injection",
                description: "Detected basic SQLi tautology pattern.",
                severity: ThreatSeverity.High,
                confidence: 1.0,
                matchedPattern: "BasicSqlInjectionPattern"
            );
        }

        // 2. Future: Add more patterns here (XSS, RCE)

        return DetectionResult.Safe();
    }
}