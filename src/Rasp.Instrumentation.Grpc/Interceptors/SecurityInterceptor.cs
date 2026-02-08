using System;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Core.Abstractions;
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
    ILogger<SecurityInterceptor> logger)
    : Interceptor
{
    private readonly int _maxScanChars = options.Value.MaxGrpcScanChars;


    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(continuation);

        InspectMessage(request as IMessage, "Incoming Request", context.Method);

        var response = await continuation(request, context).ConfigureAwait(false);

        InspectMessage(response as IMessage, "Outgoing Response", context.Method);

        return response;
    }

    private void InspectMessage(IMessage? message, string flowContext, string method)
    {
        if (message == null) return;

        var result = inspector.Inspect(message, engine, _maxScanChars);

        if (!result.IsThreat) return;
        ArgumentNullException.ThrowIfNull(result.ThreatType);
        ArgumentNullException.ThrowIfNull(result.Description);

        LogRaspBlockedFlowOnMethodTypeThreattypeReasonReason(logger, flowContext, method, result.ThreatType, result.Description);

        throw new RpcException(new Status(StatusCode.InvalidArgument, $"Security Violation: {result.Description}"));
    }

    [LoggerMessage(LogLevel.Error, "🛑 RASP Blocked {flow} on {method}. Type: {threatType}. Reason: {reason}")]
    static partial void LogRaspBlockedFlowOnMethodTypeThreattypeReasonReason(ILogger<SecurityInterceptor> logger, string flow, string method, string threatType, string reason);
}