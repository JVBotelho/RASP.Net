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

    /// <summary>
    /// Gets or sets a value indicating whether Content Security Policy (CSP) should operate in "Report-Only" mode.
    /// <para>
    /// When <c>true</c>, policy violations are reported but not blocked. This is recommended for 
    /// initial production deployments ("Learning Mode") to avoid breaking legitimate scripts.
    /// </para>
    /// <value>Default is <c>true</c>.</value>
    /// </summary>
    public bool CspReportOnly { get; set; } = true;

#pragma warning disable CA1056
    /// <summary>
    /// Gets or sets the endpoint URI where CSP violation reports will be sent by the browser.
    /// <para>
    /// This value is injected into the <c>report-uri</c> directive of the CSP header.
    /// Can be a relative path (e.g., <c>/api/csp-report</c>) or an absolute URL.
    /// </para>
    /// </summary>
    public string? CspReportUri { get; set; }
#pragma warning restore CA1056
}