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

public partial class DeserializationGuard
{
    private readonly DeserializationDetectionEngine _engine;
    private readonly RaspAlertBus _bus;
    private readonly IRaspMetrics _metrics;
    private readonly RaspOptions _options;
    private readonly ILogger<DeserializationGuard> _logger;

    public DeserializationGuard(
        DeserializationDetectionEngine engine,
        RaspAlertBus bus,
        IRaspMetrics metrics,
        IOptions<RaspOptions> options,
        ILogger<DeserializationGuard> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        
        _engine = engine;
        _bus = bus;
        _metrics = metrics;
        _options = options.Value;
        _logger = logger;
    }

    public void AnalyzeType(Type? typeToDeserialize, string context)
    {
        if (typeToDeserialize == null) return;

        var typeName = typeToDeserialize.FullName ?? typeToDeserialize.Name;
        long startTimestamp = Stopwatch.GetTimestamp();
        var result = _engine.Inspect(typeName, context);
        var elapsedMs = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;

        _metrics.RecordInspection(context, elapsedMs);

        if (result.IsThreat)
        {
            var threatType = result.ThreatType ?? "Unknown";
            var description = result.Description ?? "No description";
            var pattern = result.MatchedPattern ?? description;

            bool block = _options.BlockOnDetection; // Global BlockOnDetection

            _metrics.ReportThreat(context, threatType, block);
            var ambient = RaspExecutionContext.Current ?? new RaspContext 
            { 
                CorrelationId = Guid.NewGuid().ToString("N"), 
                Source = $"orphan:{context}", 
                StartedUtc = DateTime.UtcNow 
            };
            _bus.PushAlert(ambient, threatType, pattern, $"{context} Deserialization - Confidence: {result.Confidence}");

            if (block)
            {
                LogBlockedDeserialization(_logger, pattern, context, typeName);
                throw new RaspSecurityException(threatType, description);
            }
            else
            {
                LogAuditedDeserialization(_logger, pattern, context, typeName);
            }
        }
    }

    [LoggerMessage(EventId = 10, Level = LogLevel.Warning, Message = "RASP blocked deserialization threat. Pattern: {Pattern} Context: {Context} Type: {TypeName}")]
    private static partial void LogBlockedDeserialization(ILogger logger, string pattern, string context, string typeName);

    [LoggerMessage(EventId = 11, Level = LogLevel.Warning, Message = "RASP audited deserialization threat. Pattern: {Pattern} Context: {Context} Type: {TypeName}")]
    private static partial void LogAuditedDeserialization(ILogger logger, string pattern, string context, string typeName);
}
