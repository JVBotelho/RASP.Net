namespace Rasp.Bootstrapper.Configuration;

/// <summary>
/// Global configuration options for the RASP.
/// Allows adjusting security behavior without recompilation.
/// </summary>
public class RaspOptions
{
    /// <summary>
    /// If true, blocks detected attacks and throws an exception.
    /// If false, only logs/monitors ("Audit" Mode).
    /// Default: true (Secure by default).
    /// </summary>
    public bool BlockOnDetection { get; set; } = true;

    /// <summary>
    /// If true, enables detailed telemetry (may have performance impact).
    /// </summary>
    public bool EnableMetrics { get; set; } = true;
}