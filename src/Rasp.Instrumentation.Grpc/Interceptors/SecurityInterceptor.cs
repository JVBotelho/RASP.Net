using System.Diagnostics;
using System.Runtime.CompilerServices;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Rasp.Core.Abstractions;
using Rasp.Core.Models;

[assembly: InternalsVisibleTo("Rasp.Benchmarks")]
namespace Rasp.Instrumentation.Grpc.Interceptors;

/// <summary>
/// The main RASP barrier for gRPC services.
/// Intercepts every unary call, inspects the payload, and decides whether to proceed.
/// </summary>
public class SecurityInterceptor(IDetectionEngine detectionEngine, IRaspMetrics metrics) : Interceptor
{
    internal DetectionResult InspectInternal(string payload)
    {
        return detectionEngine.Inspect(payload, "BenchmarkContext");
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(continuation);
        
        var sw = Stopwatch.StartNew();
        string method = context.Method;

        try
        {
            if (request is not IMessage protoMessage) return await continuation(request, context).ConfigureAwait(false);
            var fields = protoMessage.Descriptor.Fields.InFieldNumberOrder();

            foreach (var field in fields)
            {
                if (field.FieldType != FieldType.String) continue;
                string? value = field.Accessor.GetValue(protoMessage) as string;

                if (string.IsNullOrEmpty(value)) continue;
                var result = detectionEngine.Inspect(value, method);

                if (!result.IsThreat) continue;
                metrics.ReportThreat("gRPC", result.ThreatType!, blocked: true);

                throw new RpcException(new Status(
                    StatusCode.PermissionDenied,
                    $"RASP Security Alert: {result.Description}"));
            }

            return await continuation(request, context).ConfigureAwait(false);
        }
        finally
        {
            sw.Stop();
            metrics.RecordInspection("gRPC", sw.Elapsed.TotalMilliseconds);
        }
    }
}