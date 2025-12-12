using Rasp.Core.Enums;

namespace Rasp.Core.Models;

public sealed record DetectionResult
{
    // OTIMIZAÇÃO: Cache da instância "Safe" para evitar alocação no hot path (99% das requisições).
    private static readonly DetectionResult _safeInstance = new() { IsThreat = false };

    /// <summary>
    /// Indicates whether a threat was detected.
    /// </summary>
    public required bool IsThreat { get; init; }

    /// <summary>
    /// The type of threat detected (e.g., "SQL Injection", "XSS").
    /// Null if no threat was detected.
    /// </summary>
    public string? ThreatType { get; init; }

    /// <summary>
    /// A detailed description of the detected threat.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// The confidence level of the detection (0.0 to 1.0).
    /// </summary>
    public double Confidence { get; init; } = 1.0;

    /// <summary>
    /// The specific pattern or rule that triggered the detection.
    /// </summary>
    public string? MatchedPattern { get; init; }

    /// <summary>
    /// The severity level of the threat.
    /// </summary>
    public ThreatSeverity Severity { get; init; } = ThreatSeverity.Medium;

    /// <summary>
    /// Returns a cached result indicating no threat was detected.
    /// ZERO ALLOCATION call.
    /// </summary>
    public static DetectionResult Safe() => _safeInstance;

    /// <summary>
    /// Creates a result indicating a threat was detected.
    /// Allocations here are acceptable as we are likely about to block the request anyway.
    /// </summary>
    public static DetectionResult Threat(
        string threatType,
        string description,
        ThreatSeverity severity = ThreatSeverity.High,
        double confidence = 1.0,
        string? matchedPattern = null) => new()
        {
            IsThreat = true,
            ThreatType = threatType,
            Description = description,
            Severity = severity,
            Confidence = confidence,
            MatchedPattern = matchedPattern
        };
}