namespace Rasp.Core.Configuration;

/// <summary>
/// Global configuration options for the RASP.
/// Allows adjusting security behavior without recompilation.
/// </summary>
public class RaspOptions
{
    public const string SectionName = "Rasp";
    
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
    
    /// <summary>
    /// Global budget for gRPC payload inspection in Characters (UTF-16).
    /// <para>
    /// Default: 262,144 chars (~512KB RAM). 
    /// If a request graph exceeds this limit, it is blocked as a potential DoS attack.
    /// </para>
    /// </summary>
    public int MaxGrpcScanChars { get; set; } = 256 * 1024;

    /// <summary>
    /// Maximum depth for recursive inspection.
    /// <para>
    /// Note: This is also hard-capped by the Source Generator (const MaxRecursionDepth = 15)
    /// to prevent StackOverflowException regardless of configuration.
    /// </para>
    /// </summary>
    public int MaxRecursionDepth { get; set; } = 15;

    /// <summary>
    /// Whether to block requests when the budget is exhausted (Fail-Secure) 
    /// or log only (Fail-Open).
    /// <para>Default: true (Block)</para>
    /// </summary>
    public bool BlockOnBudgetExhaustion { get; set; } = true;
}