using System.Diagnostics;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.Extensions.Logging.Abstractions;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine;
using Rasp.Core.Models;
using Rasp.Instrumentation.Grpc.Interceptors;
using Grpc.Core;
using LibrarySystem.Contracts.Protos;

namespace Rasp.Benchmarks;


public class NoOpDetectionEngine : IDetectionEngine
{
    public DetectionResult Inspect(string? payload, string context = "Unknown") => DetectionResult.Safe();
}

public class NoOpMetrics : IRaspMetrics
{
    public void ReportThreat(string layer, string threatType, bool blocked) { }
    public void RecordInspection(string layer, double durationMs) { }
}

public class FakeServerCallContext : ServerCallContext
{
    protected override string MethodCore => "/Library/CreateBook";
    protected override string HostCore => "localhost";
    protected override string PeerCore => "ipv4:127.0.0.1:5555";
    protected override DateTime DeadlineCore => DateTime.MaxValue;
    protected override Metadata RequestHeadersCore => Metadata.Empty;
    protected override CancellationToken CancellationTokenCore => CancellationToken.None;
    protected override Metadata ResponseTrailersCore => Metadata.Empty;
    protected override Status StatusCore { get; set; }
    protected override WriteOptions? WriteOptionsCore { get; set; }
    protected override AuthContext AuthContextCore => new AuthContext(string.Empty, new Dictionary<string, List<AuthProperty>>());

    protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options)
        => throw new NotImplementedException();

    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders)
        => Task.CompletedTask;
}

[MemoryDiagnoser]
[RankColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class InterceptorBenchmarks
{
    private SecurityInterceptor _realInterceptor = null!;
    private SecurityInterceptor _baselineInterceptor = null!;
    private readonly FakeServerCallContext _context = new();

    private CreateBookRequest _safeRequest = null!;
    private CreateBookRequest _attackRequest = null!;

    private UnaryServerMethod<CreateBookRequest, BookResponse> _continuationDelegate = null!;

    [Params(100, 1000, 10000, 100000)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var sqlEngine = new SqlInjectionDetectionEngine(NullLogger<SqlInjectionDetectionEngine>.Instance);
        var metrics = new NoOpMetrics();

        sqlEngine.Inspect("warmup ' OR 1=1");

        _realInterceptor = new SecurityInterceptor(sqlEngine, metrics);
        _baselineInterceptor = new SecurityInterceptor(new NoOpDetectionEngine(), metrics);

        var longString = new string('a', PayloadSize);

        _safeRequest = new CreateBookRequest
        {
            Title = "Clean Code: " + longString,
            Author = "Robert C. Martin",
            PublicationYear = 2008,
            Pages = 464,
            TotalCopies = 10
        };

        _attackRequest = new CreateBookRequest
        {
            Title = "Exploit",
            Author = longString + "' UNION SELECT 1, @@version -- ",
            PublicationYear = 2025,
            Pages = 1,
            TotalCopies = 1
        };

        _continuationDelegate = (req, ctx) => Task.FromResult(new BookResponse { Id = 1 });
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Overhead")]
    public async Task<BookResponse> Baseline_NoOp()
    {
        return await _baselineInterceptor.UnaryServerHandler(
            _safeRequest,
            _context,
            _continuationDelegate);
    }

    [Benchmark]
    [BenchmarkCategory("Overhead")]
    public async Task<BookResponse> RASP_Safe_Traffic()
    {
        return await _realInterceptor.UnaryServerHandler(
            _safeRequest,
            _context,
            _continuationDelegate);
    }

    [Benchmark]
    [BenchmarkCategory("Protection")]
    public async Task RASP_Block_Attack()
    {
        try
        {
            await _realInterceptor.UnaryServerHandler(
                _attackRequest,
                _context,
                _continuationDelegate);
        }
        catch (RpcException)
        {
        }
    }
}