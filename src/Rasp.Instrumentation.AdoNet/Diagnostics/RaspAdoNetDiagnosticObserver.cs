using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Linq.Expressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Core.Guard;

namespace Rasp.Instrumentation.AdoNet.Diagnostics;

public class RaspAdoNetDiagnosticObserver : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IDisposable
{
    private readonly SqlSinkGuard _guard;
    private readonly RaspOptions _options;
    private readonly ILogger<RaspAdoNetDiagnosticObserver> _logger;
    private readonly List<IDisposable> _subscriptions = new();

    // Cache for property access to avoid reflection overhead in the hot path.
    // Maps the anonymous Type to a compiled func that extracts DbCommand.
    private static readonly ConcurrentDictionary<Type, Func<object, DbCommand?>> _commandExtractors = new();

    public RaspAdoNetDiagnosticObserver(
        SqlSinkGuard guard,
        IOptions<RaspOptions> options,
        ILogger<RaspAdoNetDiagnosticObserver> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        
        _guard = guard;
        _options = options.Value;
        _logger = logger;
    }

    public void OnCompleted() { }

    public void OnError(Exception error) { }

    public void OnNext(DiagnosticListener value)
    {
        ArgumentNullException.ThrowIfNull(value);
        // Subscribe to SqlClient (both System.Data and Microsoft.Data prefixes use the same listener name)
        // Note: Microsoft.Data.Sqlite also uses SqlClientDiagnosticListener, or sometimes SqliteDiagnosticListener
        if (value.Name == "SqlClientDiagnosticListener" || value.Name == "SqliteDiagnosticListener")
        {
            _subscriptions.Add(value.Subscribe(this));
        }
    }

    public void OnNext(KeyValuePair<string, object?> value)
    {
        if (value.Value is null) return;

        // Check if the event is a command execution attempt
        if (value.Key.EndsWith("WriteCommandBefore", StringComparison.Ordinal))
        {
            var command = ExtractCommand(value.Value);
            if (command != null)
            {
                // We pass _options.BlockOnAdoNetDetection here to explicitly honor the best-effort AdoNet flag
                _guard.AnalyzeCommand(command.CommandText, "ADO.NET Sink", _options.BlockOnAdoNetDetection);
            }
        }
    }

    private static DbCommand? ExtractCommand(object payload)
    {
        var payloadType = payload.GetType();
        
        // Use cached compiled expression to extract the "Command" property
        var extractor = _commandExtractors.GetOrAdd(payloadType, CreateExtractor);
        
        return extractor(payload);
    }

    private static Func<object, DbCommand?> CreateExtractor(Type type)
    {
        var propertyInfo = type.GetProperty("Command");
        if (propertyInfo == null || !typeof(DbCommand).IsAssignableFrom(propertyInfo.PropertyType))
        {
            return _ => null;
        }

        // Generate equivalent of: payload => (DbCommand)((PayloadType)payload).Command
        var parameter = Expression.Parameter(typeof(object), "payload");
        var castPayload = Expression.Convert(parameter, type);
        var propertyAccess = Expression.Property(castPayload, propertyInfo);
        var castResult = Expression.Convert(propertyAccess, typeof(DbCommand));

        var lambda = Expression.Lambda<Func<object, DbCommand?>>(castResult, parameter);
        return lambda.Compile();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var subscription in _subscriptions)
            {
                subscription.Dispose();
            }
            _subscriptions.Clear();
        }
    }
}
