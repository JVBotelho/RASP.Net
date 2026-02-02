using System.Diagnostics;
using System.Runtime.CompilerServices;
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
public class SecurityInterceptor : Interceptor
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly IRaspMetrics _metrics;

    public SecurityInterceptor(IDetectionEngine detectionEngine, IRaspMetrics metrics)
    {
        _detectionEngine = detectionEngine;
        _metrics = metrics;
    }
    
    internal DetectionResult InspectInternal(string payload)
    {
        return _detectionEngine.Inspect(payload, "BenchmarkContext");
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var sw = Stopwatch.StartNew();
        var method = context.Method; // e.g., "/Library.Library/GetBookById"

        try
        {
            // --- 1. INSPECTION PHASE ---
            // For MVP: Convert request to string (Naive approach - Phase 2 optimization target)
            // Warning: request.ToString() in Protobuf usually returns the JSON representation.
            // This allocates memory! We will optimize this with Source Generators later.
            string payload = request?.ToString() ?? string.Empty;

            var result = _detectionEngine.Inspect(payload, method);

            if (result.IsThreat)
            {
                // --- 2. BLOCKING PHASE ---
                _metrics.ReportThreat("gRPC", result.ThreatType!, blocked: true);

                // Fail Fast with PermissionDenied (or InvalidArgument)
                throw new RpcException(new Status(
                    StatusCode.PermissionDenied,
                    $"RASP Security Alert: {result.Description}"));
            }

            // --- 3. EXECUTION PHASE ---
            return await continuation(request, context);
        }
        finally
        {
            sw.Stop();
            _metrics.RecordInspection("gRPC", sw.Elapsed.TotalMilliseconds);
        }
    }
}