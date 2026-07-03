using System;
using System.Net;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Enums;
using Rasp.Core.Extensions;
using Rasp.Core.Models;

namespace Rasp.Core.Engine;

/// <summary>
/// A specialized detection engine for Server-Side Request Forgery (SSRF).
/// Inspects outbound URIs for dangerous schemes and restricted IP ranges 
/// (e.g., loopback, cloud metadata services).
/// </summary>
public class SsrfDetectionEngine : IDetectionEngine
{
    private readonly RaspOptions _options;

    public SsrfDetectionEngine(IOptions<RaspOptions> options)
    {
        _options = options?.Value ?? new RaspOptions();
    }

    private static bool IsDangerousScheme(string scheme)
    {
        return string.Equals(scheme, "file", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(scheme, "gopher", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(scheme, "ftp", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(scheme, "dict", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(scheme, "ldap", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(scheme, "jar", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(scheme, "netdoc", StringComparison.OrdinalIgnoreCase);
    }

    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload)) return DetectionResult.Safe();

        // Fast string checks for dangerous schemes before full parsing
        if (payload.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("gopher:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("ftp:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("dict:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("ldap:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("jar:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("netdoc:", StringComparison.OrdinalIgnoreCase))
        {
            return DetectionResult.Threat("SSRF", "Dangerous URI scheme detected", ThreatSeverity.Critical, 1.0, "DangerousScheme");
        }

        if (Uri.TryCreate(payload, UriKind.Absolute, out var uri))
        {
            return Inspect(uri, context);
        }

        return DetectionResult.Safe();
    }

    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty) return DetectionResult.Safe();
        // Since Uri requires string, delegate to string overload
        return Inspect(payload.ToString(), context);
    }

    public DetectionResult Inspect(Uri uri, string context = "Unknown")
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (IsDangerousScheme(uri.Scheme))
        {
            return DetectionResult.Threat("SSRF", "Dangerous URI scheme detected", ThreatSeverity.Critical, 1.0, "DangerousScheme");
        }

        // Optionally attempt to parse obfuscated IP directly without DNS
        if (IPAddress.TryParse(uri.Host, out var parsedIp))
        {
            var ipResult = Inspect(parsedIp, context);
            if (ipResult.IsThreat) return ipResult;
        }

        return DetectionResult.Safe();
    }

    private static readonly IPAddress AlibabaImdsAddress = IPAddress.Parse("100.100.100.200");

    public DetectionResult Inspect(IPAddress ip, string context = "Unknown")
    {
        ArgumentNullException.ThrowIfNull(ip);
        var blocks = _options.SsrfBlockedIpBlocks;

        if (blocks == RaspSsrfIpBlock.None)
        {
            return DetectionResult.Safe();
        }

        // Normalize once, up front: a dual-stack socket connects an IPv4-mapped IPv6 address
        // (::ffff:100.100.100.200) to the exact same destination as its IPv4 form, but
        // IPAddress.Equals compares AddressFamily too, so an un-normalized mapped address
        // silently bypasses the Equals-based checks below (Unspecified, AlibabaIMDS). The
        // IsX() extension methods already normalize internally (IsLinkLocal, IsUniqueLocal,
        // IsPrivateNetwork), and IPAddress.IsLoopback handles mapped addresses natively, so
        // normalizing here is redundant-but-harmless for those - it exists specifically to
        // close the gap for the plain .Equals() checks.
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if ((blocks & RaspSsrfIpBlock.Loopback) == RaspSsrfIpBlock.Loopback && IPAddress.IsLoopback(ip))
        {
            return DetectionResult.Threat("SSRF", "Loopback access detected", ThreatSeverity.Critical, 1.0, "LoopbackAccess");
        }

        if ((blocks & RaspSsrfIpBlock.Unspecified) == RaspSsrfIpBlock.Unspecified && (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)))
        {
            return DetectionResult.Threat("SSRF", "Wildcard IP access detected", ThreatSeverity.Critical, 0.9, "WildcardIP");
        }

        if ((blocks & RaspSsrfIpBlock.LinkLocal) == RaspSsrfIpBlock.LinkLocal && ip.IsLinkLocal())
        {
            return DetectionResult.Threat("SSRF", "Link-Local / Cloud metadata service access detected", ThreatSeverity.Critical, 1.0, "LinkLocal");
        }

        if ((blocks & RaspSsrfIpBlock.AlibabaIMDS) == RaspSsrfIpBlock.AlibabaIMDS && ip.Equals(AlibabaImdsAddress))
        {
            return DetectionResult.Threat("SSRF", "Alibaba Cloud metadata service access detected", ThreatSeverity.Critical, 1.0, "AlibabaIMDS");
        }

        if ((blocks & RaspSsrfIpBlock.UniqueLocal) == RaspSsrfIpBlock.UniqueLocal && ip.IsUniqueLocal())
        {
            return DetectionResult.Threat("SSRF", "Unique Local IP access detected", ThreatSeverity.Critical, 0.9, "UniqueLocal");
        }

        if ((blocks & RaspSsrfIpBlock.PrivateNetwork) == RaspSsrfIpBlock.PrivateNetwork && ip.IsPrivateNetwork())
        {
            return DetectionResult.Threat("SSRF", "Private Network access detected", ThreatSeverity.High, 0.9, "PrivateNetwork");
        }

        return DetectionResult.Safe();
    }
}
