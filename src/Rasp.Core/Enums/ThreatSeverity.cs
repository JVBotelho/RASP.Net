namespace Rasp.Core.Enums;

/// <summary>
/// Defines the severity levels for detected threats.
/// </summary>
public enum ThreatSeverity
{
    /// <summary>
    /// Informational - suspicious but not necessarily malicious.
    /// </summary>
    Info = 0,

    /// <summary>
    /// Low severity - minor security concern.
    /// </summary>
    Low = 1,

    /// <summary>
    /// Medium severity - potential security issue.
    /// </summary>
    Medium = 2,

    /// <summary>
    /// High severity - likely attack attempt.
    /// </summary>
    High = 3,

    /// <summary>
    /// Critical severity - confirmed attack with high confidence.
    /// </summary>
    Critical = 4
}