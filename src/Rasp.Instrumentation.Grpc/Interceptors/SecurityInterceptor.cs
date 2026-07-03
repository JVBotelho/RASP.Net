using System;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Core.Abstractions;
using Rasp.Core.Infrastructure;
using Rasp.Core.Context;
using Google.Protobuf;

namespace Rasp.Instrumentation.Grpc.Interceptors;

/// <summary>
/// The Runtime Gatekeeper for gRPC traffic.
/// <para>
/// Refactored to depend only on Core abstractions and Options, 
/// strictly following Dependency Inversion Principle.
/// </para>
/// </summary>
public partial class SecurityInterceptor(
    IDetectionEngine engine,
    IGrpcMessageInspector inspector,
    IOptions<RaspOptions> options,
    IRaspMetrics metrics,
    RaspAlertBus bus,
    ILogger<SecurityInterceptor> logger)
    : Interceptor
{
    // Captured at startup. IOptionsMonitor is not used for performance reasons, 
    // so runtime changes to BlockOnDetection require a restart.
    private readonly int _maxScanChars = options.Value.MaxGrpcScanChars;
    private readonly bool _blockOnDetection = options.Value.BlockOnDetection;
    private readonly bool _enableMetrics = options.Value.EnableMetrics;


    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(continuation);

        var start = System.Diagnostics.Stopwatch.GetTimestamp();

        var correlationId = Guid.NewGuid().ToString("N");
        var raspContext = new RaspContext
        {
            CorrelationId = correlationId,
            Source = $"gRPC {context.Method}",
            RemoteId = context.Peer,
            TraceId = null, // Can be pulled from headers/Activity if available
            StartedUtc = DateTime.UtcNow
        };

        using var scope = RaspExecutionContext.BeginScope(raspContext);

        InspectMessage(request as IMessage, "Incoming Request", context.Method, raspContext);

        var response = await continuation(request, context).ConfigureAwait(false);

        InspectMessage(response as IMessage, "Outgoing Response", context.Method, raspContext);

        if (_enableMetrics)
        {
            var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            metrics.RecordInspection("gRPC", elapsed);
        }

        return response;
    }

    private void InspectMessage(IMessage? message, string flowContext, string method, RaspContext raspContext)
    {
        if (message == null) return;

        var result = inspector.Inspect(message, engine, _maxScanChars);

        if (!result.IsThreat) return;
        ArgumentNullException.ThrowIfNull(result.ThreatType);
        ArgumentNullException.ThrowIfNull(result.Description);

        LogThreatBlocked(flowContext, method, result.ThreatType, result.Description);

        bus.PushAlert(raspContext, result.ThreatType, result.MatchedPattern ?? result.Description, $"Flow: {flowContext}, Method: {method}");
        if (_enableMetrics)
        {
            metrics.ReportThreat("gRPC", result.ThreatType, _blockOnDetection);
        }

        if (_blockOnDetection)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, $"Security Violation: {result.Description}"));
        }
    }

    [LoggerMessage(EventId = 1, Level = LogLevel.Error, Message = "🛑 RASP Blocked {flow} on {method}. Type: {threatType}. Reason: {reason}")]
    partial void LogThreatBlocked(string flow, string method, string threatType, string reason);
}