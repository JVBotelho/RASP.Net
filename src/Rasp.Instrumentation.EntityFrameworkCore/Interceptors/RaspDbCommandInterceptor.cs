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

using Microsoft.Extensions.Logging;

using Rasp.Core.Guard;

namespace Rasp.Instrumentation.EntityFrameworkCore.Interceptors;

public class RaspDbCommandInterceptor : DbCommandInterceptor
{
    private readonly SqlSinkGuard _guard;

    public RaspDbCommandInterceptor(SqlSinkGuard guard)
    {
        ArgumentNullException.ThrowIfNull(guard);

        _guard = guard;
    }
    private void AnalyzeCommand(DbCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        _guard.AnalyzeCommand(command.CommandText, "EF Core Sink");
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
