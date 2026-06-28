using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Rasp.Core.Context;

namespace Rasp.Instrumentation.AspNetCore;

/// <summary>
/// Middleware to establish the RaspContext for HTTP requests that do not pass through gRPC.
/// This enables Taint Tracking and Ambient Execution Context provenance for raw HTTP endpoints.
/// </summary>
public class RaspContextMiddleware
{
    private readonly RequestDelegate _next;

    public RaspContextMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var correlationId = Activity.Current?.Id ?? context.TraceIdentifier ?? Guid.NewGuid().ToString("N");
        var remoteIp = context.Connection.RemoteIpAddress?.ToString();

        var raspContext = new RaspContext
        {
            CorrelationId = correlationId,
            Source = $"HTTP {context.Request.Method} {context.Request.Path}",
            RemoteId = remoteIp,
            TraceId = Activity.Current?.TraceId.ToString(),
            StartedUtc = DateTime.UtcNow
        };

        using var scope = RaspExecutionContext.BeginScope(raspContext);

        // Query string values are the actual string instances a handler reads via
        // context.Request.Query[...] - marking them here (not after model binding) means
        // the same instance is what a downstream sink sees, so RaspTaintSensor's
        // identity-based lookup finds it. Route values aren't marked: this middleware runs
        // before UseRouting() (see RaspStartupFilter), so they aren't populated yet here.
        // Request body / form values aren't marked either - they're deserialized into new
        // string instances downstream, which this middleware has no handle on; see
        // src/Rasp.Native.Profiler/README.md for the current v1 taint-propagation scope.
        foreach (var query in context.Request.Query)
        {
            foreach (var value in query.Value)
            {
                RaspTaintSensor.MarkTainted(value);
            }
        }

        await _next(context).ConfigureAwait(false);
    }
}
