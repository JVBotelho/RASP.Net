using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Logging.Abstractions;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine;
using Rasp.Core.Models;
using Rasp.Instrumentation.Grpc.Interceptors;

namespace Rasp.Benchmarks;

public class NoOpMetrics : IRaspMetrics
{
    public void ReportThreat(string layer, string threatType, bool blocked) { }
    public void RecordInspection(string layer, double durationMs) { }
}

public class NoOpDetectionEngine : IDetectionEngine
{
    public DetectionResult Inspect(string payload, string context)
    {
        if (string.IsNullOrEmpty(payload)) return DetectionResult.Safe();
        return DetectionResult.Safe();
    }
}

[MemoryDiagnoser]
[RankColumn]
public class InterceptorBenchmarks
{
    private SecurityInterceptor _realInterceptor = null!;
    private SecurityInterceptor _baselineInterceptor = null!;

    [Params(100, 1000, 10000)] 
    public int PayloadSize { get; set; }

    private string _simpleSafePayload = null!;
    private string _realisticSafePayload = null!;
    private string _attackPayload = null!;

    [GlobalSetup]
    public void Setup()
    {
        var sqlEngine = new SqlInjectionDetectionEngine(
            NullLogger<SqlInjectionDetectionEngine>.Instance
        );
        var metrics = new NoOpMetrics();
        
        _realInterceptor = new SecurityInterceptor(sqlEngine, metrics);
        _baselineInterceptor = new SecurityInterceptor(new NoOpDetectionEngine(), metrics);

        _simpleSafePayload = new string('a', PayloadSize);

        _realisticSafePayload = GenerateRealisticPayload(PayloadSize);

        _attackPayload = GenerateRealisticPayload(PayloadSize / 2) + 
                         "' UNION SELECT 1, @@version -- " + 
                         GenerateRealisticPayload(PayloadSize / 2);
    }

    private static string GenerateRealisticPayload(int length)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}:\"";
        return string.Create(length, chars, (span, charSet) => {
            for(int i=0; i < span.Length; i++)
                span[i] = charSet[i % charSet.Length];
        });
    }

    [Benchmark(Baseline = true)]
    public DetectionResult Baseline_NoOp()
    {
        return _baselineInterceptor.InspectInternal(_simpleSafePayload);
    }

    [Benchmark]
    public DetectionResult RASP_SimpleSafe()
    {
        return _realInterceptor.InspectInternal(_simpleSafePayload);
    }

    [Benchmark]
    public DetectionResult RASP_RealisticSafe()
    {
        return _realInterceptor.InspectInternal(_realisticSafePayload);
    }

    [Benchmark]
    public DetectionResult RASP_Attack()
    {
        return _realInterceptor.InspectInternal(_attackPayload);
    }
}