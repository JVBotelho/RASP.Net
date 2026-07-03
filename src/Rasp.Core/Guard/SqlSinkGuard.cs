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

public partial class SqlSinkGuard
{
    private readonly SqlSinkDetectionEngine _engine;
    private readonly RaspAlertBus _bus;
    private readonly IRaspMetrics _metrics;
    private readonly RaspOptions _options;
    private readonly ILogger<SqlSinkGuard> _logger;

    public SqlSinkGuard(
        SqlSinkDetectionEngine engine,
        RaspAlertBus bus,
        IRaspMetrics metrics,
        IOptions<RaspOptions> options,
        ILogger<SqlSinkGuard> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _engine = engine;
        _bus = bus;
        _metrics = metrics;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Performs security analysis of the SQL command, pushing metrics and alerts.
    /// If a threat is detected and the corresponding block option is true, throws a RaspSecurityException.
    /// </summary>
    /// <param name="commandText">The SQL command text to analyze.</param>
    /// <param name="context">The context/source (e.g. EF Core Sink, ADO.NET DiagnosticListener).</param>
    /// <param name="shouldBlock">Whether to block if a threat is found. If null, uses global BlockOnDetection.</param>
    public void AnalyzeCommand(string commandText, string context, bool? shouldBlock = null)
    {
        if (string.IsNullOrEmpty(commandText)) return;

        long startTimestamp = Stopwatch.GetTimestamp();
        var result = _engine.Inspect(commandText, context);
        var elapsedMs = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;

        _metrics.RecordInspection(context, elapsedMs);

        if (result.IsThreat)
        {
            var threatType = result.ThreatType ?? "Unknown";
            var description = result.Description ?? "No description";
            var pattern = result.MatchedPattern ?? description;

            bool block = shouldBlock ?? _options.BlockOnDetection;

            _metrics.ReportThreat(context, threatType, block);
            var ambient = RaspExecutionContext.Current ?? new RaspContext
            {
                CorrelationId = Guid.NewGuid().ToString("N"),
                Source = $"orphan:{context}",
                StartedUtc = DateTime.UtcNow
            };

            // Forensic enrichment only - does NOT gate blocking. v1 taint propagation only
            // covers System.String::Concat(string, string) (see
            // src/Rasp.Native.Profiler/README.md), so a real attack reaching this sink via
            // any other path (StringBuilder, interpolation, EF parameter binding that
            // happens to build raw SQL, etc.) would show IsTainted == false despite being
            // a genuine attack. Gating on taint would turn that gap into a false negative;
            // this signal exists to help a SOC analyst triage, not to suppress alerts.
            bool isTainted = RaspTaintSensor.IsTainted(commandText);
            var taintSuffix = isTainted ? " [Tainted]" : string.Empty;

            _bus.PushAlert(ambient, threatType, pattern, $"{context} Execution - Confidence: {result.Confidence}{taintSuffix}");

            if (block)
            {
                LogBlockedSqlSink(_logger, pattern, context, isTainted);
                throw new RaspSecurityException(threatType, description);
            }
            else
            {
                LogAuditedSqlSink(_logger, pattern, context, isTainted);
            }
        }
    }

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "RASP blocked SQL sink threat. Pattern: {Pattern} Context: {Context} Tainted: {IsTainted}")]
    private static partial void LogBlockedSqlSink(ILogger logger, string pattern, string context, bool isTainted);

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning, Message = "RASP audited SQL sink threat. Pattern: {Pattern} Context: {Context} Tainted: {IsTainted}")]
    private static partial void LogAuditedSqlSink(ILogger logger, string pattern, string context, bool isTainted);
}
