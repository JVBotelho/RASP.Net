using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Exceptions;
using Rasp.Core.Infrastructure;
using Rasp.Core.Context;

namespace Rasp.Core.Guard;

public partial class SsrfGuard
{
    private readonly SsrfDetectionEngine _engine;
    private readonly RaspAlertBus _bus;
    private readonly IRaspMetrics _metrics;
    private readonly RaspOptions _options;
    private readonly ILogger<SsrfGuard> _logger;

    public SsrfGuard(
        SsrfDetectionEngine engine,
        RaspAlertBus bus,
        IRaspMetrics metrics,
        IOptions<RaspOptions> options,
        ILogger<SsrfGuard> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        
        _engine = engine;
        _bus = bus;
        _metrics = metrics;
        _options = options.Value;
        _logger = logger;
    }

    public void AnalyzeUri(Uri? requestUri, string context)
    {
        if (requestUri == null) return;

        long startTimestamp = Stopwatch.GetTimestamp();
        var result = _engine.Inspect(requestUri, context);
        var elapsedMs = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;

        _metrics.RecordInspection(context, elapsedMs);

        if (result.IsThreat)
        {
            var threatType = result.ThreatType ?? "Unknown";
            var description = result.Description ?? "No description";
            var pattern = result.MatchedPattern ?? description;

            bool block = _options.BlockOnSsrfDetection;

            _metrics.ReportThreat(context, threatType, block);
            var ambient = RaspExecutionContext.Current ?? new RaspContext 
            { 
                CorrelationId = Guid.NewGuid().ToString("N"), 
                Source = $"orphan:{context}", 
                StartedUtc = DateTime.UtcNow 
            };
            _bus.PushAlert(ambient, threatType, pattern, $"{context} Outbound Request - Confidence: {result.Confidence}");

            if (block)
            {
                LogBlockedSsrf(_logger, pattern, context, requestUri.ToString());
                throw new RaspSecurityException(threatType, description);
            }
            else
            {
                LogAuditedSsrf(_logger, pattern, context, requestUri.ToString());
            }
        }
    }

    public void AnalyzeIp(System.Net.IPAddress ip, string context)
    {
        if (ip == null) return;

        long startTimestamp = Stopwatch.GetTimestamp();
        var result = _engine.Inspect(ip, context);
        var elapsedMs = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;

        _metrics.RecordInspection(context, elapsedMs);

        if (result.IsThreat)
        {
            var threatType = result.ThreatType ?? "Unknown";
            var description = result.Description ?? "No description";
            var pattern = result.MatchedPattern ?? description;

            bool block = _options.BlockOnSsrfDetection;

            _metrics.ReportThreat(context, threatType, block);
            var ambient = RaspExecutionContext.Current ?? new RaspContext 
            { 
                CorrelationId = Guid.NewGuid().ToString("N"), 
                Source = $"orphan:{context}", 
                StartedUtc = DateTime.UtcNow 
            };
            _bus.PushAlert(ambient, threatType, pattern, $"{context} Outbound Request IP - Confidence: {result.Confidence}");

            if (block)
            {
                LogBlockedSsrf(_logger, pattern, context, ip.ToString());
                throw new RaspSecurityException(threatType, description);
            }
            else
            {
                LogAuditedSsrf(_logger, pattern, context, ip.ToString());
            }
        }
    }

    [LoggerMessage(EventId = 4, Level = LogLevel.Warning, Message = "RASP blocked SSRF threat. Pattern: {Pattern} Context: {Context} URI: {Uri}")]
    private static partial void LogBlockedSsrf(ILogger logger, string pattern, string context, string uri);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning, Message = "RASP audited SSRF threat. Pattern: {Pattern} Context: {Context} URI: {Uri}")]
    private static partial void LogAuditedSsrf(ILogger logger, string pattern, string context, string uri);
}
