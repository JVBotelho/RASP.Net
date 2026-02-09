using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;

// ReSharper disable once CheckNamespace
namespace Rasp.Instrumentation.AspNetCore.Middleware;

/// <summary>
/// A hardening middleware that injects security headers into HTTP responses.
/// <para>
/// This middleware acts as a "vaccine" for the browser, applying Content Security Policy (CSP),
/// Anti-MIME Sniffing, and Frame Options to neutralize XSS, Clickjacking, and other client-side vectors
/// that might bypass input filtering.
/// </para>
/// </summary>
public sealed class RaspSecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    private readonly string _cspHeaderName;
    private readonly string _cspHeaderValue;

    private const string HeaderCsp = "Content-Security-Policy";
    private const string HeaderCspReportOnly = "Content-Security-Policy-Report-Only";
    private const string HeaderNoSniff = "X-Content-Type-Options";
    private const string HeaderFrameOptions = "X-Frame-Options";

    public RaspSecurityHeadersMiddleware(RequestDelegate next, IOptions<RaspOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _next = next;
        var opt = options.Value;

        _cspHeaderName = opt.CspReportOnly ? HeaderCspReportOnly : HeaderCsp;

        if (!string.IsNullOrEmpty(opt.CspReportUri) &&
            !Uri.TryCreate(opt.CspReportUri, UriKind.RelativeOrAbsolute, out _))
        {
            throw new ArgumentException(
                $"Invalid RASP Configuration: '{opt.CspReportUri}' is not a valid URI for CspReportUri.");
        }

        var sb = new StringBuilder(
            "default-src 'self'; " +
            "object-src 'none'; " +
            "frame-ancestors 'none'; " +
            "upgrade-insecure-requests; " +
            "block-all-mixed-content;");

        if (!string.IsNullOrEmpty(opt.CspReportUri))
        {
            sb.Append(" report-uri ");
            sb.Append(opt.CspReportUri);
            sb.Append(';');
        }

        _cspHeaderValue = sb.ToString();
    }

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Response.OnStarting(ApplySecurityHeaders, context);
        return _next(context);
    }

    private Task ApplySecurityHeaders(object state)
    {
        var context = (HttpContext)state;
        var headers = context.Response.Headers;

        if (!headers.ContainsKey(HeaderNoSniff))
        {
            headers[HeaderNoSniff] = "nosniff";
        }

        if (!headers.ContainsKey(HeaderFrameOptions))
        {
            headers[HeaderFrameOptions] = "SAMEORIGIN";
        }

        if (!headers.ContainsKey(_cspHeaderName))
        {
            headers[_cspHeaderName] = _cspHeaderValue;
        }

        return Task.CompletedTask;
    }
}