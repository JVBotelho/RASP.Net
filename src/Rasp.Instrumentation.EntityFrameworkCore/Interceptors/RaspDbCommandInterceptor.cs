using System.Data.Common;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Exceptions;
using Rasp.Core.Infrastructure;

namespace Rasp.Instrumentation.EntityFrameworkCore.Interceptors;

public class RaspDbCommandInterceptor : DbCommandInterceptor
{
    private readonly SqlSinkDetectionEngine _engine;
    private readonly RaspAlertBus _bus;
    private readonly IRaspMetrics _metrics;
    private readonly RaspOptions _options;

    public RaspDbCommandInterceptor(
        SqlSinkDetectionEngine engine,
        RaspAlertBus bus,
        IRaspMetrics metrics,
        IOptions<RaspOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        
        _engine = engine;
        _bus = bus;
        _metrics = metrics;
        _options = options.Value;
    }

    private void AnalyzeCommand(DbCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var stopwatch = Stopwatch.StartNew();
        var commandText = command.CommandText;

        var result = _engine.Inspect(commandText, context: "EF Core Sink");

        stopwatch.Stop();
        _metrics.RecordInspection("EntityFrameworkCore", stopwatch.Elapsed.TotalMilliseconds);

        if (result.IsThreat)
        {
            var threatType = result.ThreatType ?? "Unknown";
            var description = result.Description ?? "No description";
            var pattern = result.MatchedPattern ?? description;

            _metrics.ReportThreat("EntityFrameworkCore", threatType, _options.BlockOnDetection);
            _bus.PushAlert(threatType, pattern, $"EF Core Command Execution - Confidence: {result.Confidence}");

            if (_options.BlockOnDetection)
            {
                throw new RaspSecurityException(threatType, description);
            }
        }
    }

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
    {
        AnalyzeCommand(command);
        return base.ReaderExecuting(command, eventData, result);
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        AnalyzeCommand(command);
        return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
    {
        AnalyzeCommand(command);
        return base.NonQueryExecuting(command, eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        AnalyzeCommand(command);
        return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
    {
        AnalyzeCommand(command);
        return base.ScalarExecuting(command, eventData, result);
    }

    public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        AnalyzeCommand(command);
        return base.ScalarExecutingAsync(command, eventData, result, cancellationToken);
    }
}
