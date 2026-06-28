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
    /// If true, attempts to block detected attacks in the ADO.NET base layer (SqlClient) by 
    /// synchronously throwing an exception inside the `DiagnosticListener` delegate.
    /// 
    /// WARNING: This block is "best-effort" and can silently degrade to "observe-only" (fail-open) 
    /// if future versions of libraries like Microsoft.Data.SqlClient wrap the `DiagnosticListener` 
    /// delegates with try/catch blocks.
    /// Default: true.
    /// </summary>
    public bool BlockOnAdoNetDetection { get; set; } = true;

    /// <summary>
    /// If true, blocks detected Server-Side Request Forgery (SSRF) threats.
    /// If false, logs the threat but allows the connection (Audit mode).
    /// Default: true.
    /// </summary>
    public bool BlockOnSsrfDetection { get; set; } = true;

    /// <summary>
    /// Specifies which IP ranges should be blocked by the SSRF engine.
    /// Defaults to blocking Loopback, Unspecified, LinkLocal, AlibabaIMDS, and UniqueLocal.
    /// Internal/Private Networks (RFC 1918) are NOT blocked by default to prevent breaking
    /// legitimate microservice communication, but can be enabled here.
    /// </summary>
    public Enums.RaspSsrfIpBlock SsrfBlockedIpBlocks { get; set; } = Enums.RaspSsrfIpBlock.AllCritical;

    /// <summary>
    /// How long a hostname's DNS resolution may be cached before the SSRF guard's Layer 2
    /// (<c>SocketsHttpHandler.ConnectCallback</c>) re-resolves it.
    /// <para>
    /// Default: <see cref="TimeSpan.Zero"/> (disabled - every outbound call re-resolves DNS fresh).
    /// This is the secure default: Layer 2 exists specifically to defend against DNS rebinding
    /// (a hostname resolves to a safe IP at validation time, then an attacker-controlled DNS
    /// server repoints it to an internal/loopback address before the connection is actually
    /// made), and caching a "safe" verdict for any duration reopens that window for the length
    /// of the cache.
    /// </para>
    /// <para>
    /// Only raise this above zero if the destinations reached through RASP-instrumented
    /// <c>HttpClient</c>s are a small, fixed set of trusted internal services - never for
    /// clients that fetch attacker-influenceable URLs (webhooks, user-supplied links, SSRF-prone
    /// proxies), which is exactly the traffic this guard exists to protect.
    /// </para>
    /// </summary>
    public TimeSpan SsrfDnsCacheDuration { get; set; } = TimeSpan.Zero;

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

#pragma warning disable CA1002, CA2227
    /// <summary>
    /// Allowed root directories for file-system access.
    /// <para>
    /// Fail-<b>open</b> when empty: every path is allowed, i.e. Path Traversal checking is
    /// disabled. This is the opposite default from <see cref="AllowedProcesses"/> below -
    /// intentional, not an inconsistency: most web apps read/write files as a routine part of
    /// normal operation, so a Path Traversal check that defaulted to blocking everything
    /// would break out of the box. Set this explicitly to enable enforcement.
    /// </para>
    /// </summary>
    public System.Collections.Generic.List<string> AllowedFileRoots { get; set; } = new();

    /// <summary>
    /// Allowlist of executable names permitted for <c>Process.Start</c>.
    /// <para>
    /// Fail-<b>closed</b> when empty: every <c>Process.Start</c> call is blocked (see
    /// <see cref="Engine.CommandInjectionDetectionEngine"/>'s default-deny check). This is
    /// the opposite default from <see cref="AllowedFileRoots"/> above - intentional, not an
    /// inconsistency: spawning child processes is rare in a typical web app and each one is a
    /// significant capability, so defaulting to "none allowed" until explicitly configured is
    /// the safer posture for whoever opts into Phase B runtime patching.
    /// </para>
    /// </summary>
    public System.Collections.Generic.List<string> AllowedProcesses { get; set; } = new();
#pragma warning restore CA1002, CA2227

    /// <summary>
    /// Se true, bloqueia ações flagradas pelo runtime patching (Path Traversal e Command Injection).
    /// </summary>
    public bool BlockOnRuntimePatchingDetection { get; set; } = true;
}