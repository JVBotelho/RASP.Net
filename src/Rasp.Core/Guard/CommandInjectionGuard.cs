using System;
using System.Collections.Generic;
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

public partial class CommandInjectionGuard
{
    private readonly CommandInjectionDetectionEngine _engine;
    private readonly RaspAlertBus _bus;
    private readonly IRaspMetrics _metrics;
    private readonly RaspOptions _options;
    private readonly ILogger<CommandInjectionGuard> _logger;

    public CommandInjectionGuard(
        CommandInjectionDetectionEngine engine,
        RaspAlertBus bus,
        IRaspMetrics metrics,
        IOptions<RaspOptions> options,
        ILogger<CommandInjectionGuard> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _engine = engine;
        _bus = bus;
        _metrics = metrics;
        _options = options.Value;
        _logger = logger;
    }

    public void AnalyzeProcessExecution(string executablePath, IReadOnlyList<string> arguments, bool useShellExecute, string context)
    {
        if (string.IsNullOrWhiteSpace(executablePath)) return;

        long startTimestamp = Stopwatch.GetTimestamp();
        var result = _engine.Inspect(executablePath, arguments, useShellExecute, context);
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
            _bus.PushAlert(ambient, threatType, pattern, $"{context} Process Execution - Confidence: {result.Confidence}");

            if (block)
            {
                LogBlockedCommandInjection(_logger, pattern, context, executablePath);
                throw new RaspSecurityException(threatType, description);
            }
            else
            {
                LogAuditedCommandInjection(_logger, pattern, context, executablePath);
            }
        }
    }

    [LoggerMessage(EventId = 8, Level = LogLevel.Warning, Message = "RASP blocked command injection threat. Pattern: {Pattern} Context: {Context} Executable: {ExecutablePath}")]
    private static partial void LogBlockedCommandInjection(ILogger logger, string pattern, string context, string executablePath);

    [LoggerMessage(EventId = 9, Level = LogLevel.Warning, Message = "RASP audited command injection threat. Pattern: {Pattern} Context: {Context} Executable: {ExecutablePath}")]
    private static partial void LogAuditedCommandInjection(ILogger logger, string pattern, string context, string executablePath);
}
