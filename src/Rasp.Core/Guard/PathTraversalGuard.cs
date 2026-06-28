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

public partial class PathTraversalGuard
{
    private readonly PathTraversalDetectionEngine _engine;
    private readonly RaspAlertBus _bus;
    private readonly IRaspMetrics _metrics;
    private readonly RaspOptions _options;
    private readonly ILogger<PathTraversalGuard> _logger;

    public PathTraversalGuard(
        PathTraversalDetectionEngine engine,
        RaspAlertBus bus,
        IRaspMetrics metrics,
        IOptions<RaspOptions> options,
        ILogger<PathTraversalGuard> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        
        _engine = engine;
        _bus = bus;
        _metrics = metrics;
        _options = options.Value;
        _logger = logger;
    }

    public void AnalyzePath(string path, string context)
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        long startTimestamp = Stopwatch.GetTimestamp();
        var result = _engine.Inspect(path, context);
        var elapsedMs = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;

        _metrics.RecordInspection(context, elapsedMs);

        if (result.IsThreat)
        {
            var threatType = result.ThreatType ?? "Unknown";
            var description = result.Description ?? "No description";
            var pattern = result.MatchedPattern ?? description;

            bool block = _options.BlockOnRuntimePatchingDetection;

            _metrics.ReportThreat(context, threatType, block);
            var ambient = RaspExecutionContext.Current ?? new RaspContext 
            { 
                CorrelationId = Guid.NewGuid().ToString("N"), 
                Source = $"orphan:{context}", 
                StartedUtc = DateTime.UtcNow 
            };
            _bus.PushAlert(ambient, threatType, pattern, $"{context} File Access - Confidence: {result.Confidence}");

            if (block)
            {
                LogBlockedPathTraversal(_logger, pattern, context, path);
                throw new RaspSecurityException(threatType, description);
            }
            else
            {
                LogAuditedPathTraversal(_logger, pattern, context, path);
            }
        }
    }

    [LoggerMessage(EventId = 6, Level = LogLevel.Warning, Message = "RASP blocked path traversal threat. Pattern: {Pattern} Context: {Context} Path: {Path}")]
    private static partial void LogBlockedPathTraversal(ILogger logger, string pattern, string context, string path);

    [LoggerMessage(EventId = 7, Level = LogLevel.Warning, Message = "RASP audited path traversal threat. Pattern: {Pattern} Context: {Context} Path: {Path}")]
    private static partial void LogAuditedPathTraversal(ILogger logger, string pattern, string context, string path);
}
