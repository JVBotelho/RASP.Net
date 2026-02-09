using BenchmarkDotNet.Attributes;
using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using LibrarySystem.Contracts.Protos;
using Rasp.Core.Infrastructure;
using Rasp.Instrumentation.Grpc.Interceptors;
using Rasp.Benchmarks.Models;
using Rasp.Benchmarks.Stubs;

// using Rasp.Benchmarks.Stubs; 

namespace Rasp.Benchmarks;

[MemoryDiagnoser]
[InProcess]
public class DeepNestingBenchmark : IDisposable
{
    private DeepTargetServiceRaspInterceptor _sourceGenInterceptor = null!;
    private SecurityInterceptor _reflectionInterceptor = null!;

    // Payloads
    private DeepRequest _cleanRequest = null!;
    private DeepRequest _infectedRequest = null!;

    private readonly FakeServerCallContext _context = new("/Library/DeepOperation");
    private readonly Task<BookResponse> _cachedResponse = Task.FromResult(new BookResponse());

    private RaspAlertBus _alertBus = null!;
    private CancellationTokenSource _cts = null!;
    private Task _consumerTask = null!;
    private bool _disposed;

    [GlobalSetup]
    public void Setup()
    {
        // 1. Engines (Logger Null para não sujar o benchmark com I/O)
        var sqlEngine = new SqlInjectionDetectionEngine(NullLogger<SqlInjectionDetectionEngine>.Instance);
        var xssEngine = new XssDetectionEngine();
        _alertBus = new RaspAlertBus();
        _cts = new CancellationTokenSource();

        for (int i = 0; i < 100; i++)
        {
            _alertBus.PushAlert("Test", "Payload", "Context");
        }

        _consumerTask = Task.Run(async () =>
        {
            try
            {
                await foreach (var _ in _alertBus.ReadAlertsAsync(_cts.Token).ConfigureAwait(false))
                {
                    // No-Op: Apenas consome para liberar a memória na Gen0
                }
            }
            catch (OperationCanceledException) { }
        });

        // 2. Interceptors
        _sourceGenInterceptor = new DeepTargetServiceRaspInterceptor(xssEngine, sqlEngine, _alertBus);

        var reflectionInspector = new RecursiveReflectionInspector();
        var opts = Options.Create(new RaspOptions());
        var composite = new CompositeDetectionEngine(sqlEngine, xssEngine);
        _reflectionInterceptor = new SecurityInterceptor(composite, reflectionInspector, opts, NullLogger<SecurityInterceptor>.Instance);

        // 3. CLEAN REQUEST (15 Níveis, Payload Seguro no fundo)
        _cleanRequest = BuildChain(15, safe: true);

        // 4. INFECTED REQUEST (15 Níveis, Payload XSS no Nível 7)
        _infectedRequest = BuildChain(15, safe: false);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        Dispose();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            if (_cts != null)
            {
                _cts.Cancel();
                try
                {
                    // Aguarda brevemente o consumidor terminar
                    _consumerTask?.Wait(500);
                }
                catch (OperationCanceledException)
                {
                    // Ignora erros de cancelamento/timeout no cleanup
                }
                _cts.Dispose();
            }
        }

        _disposed = true;
    }

    private DeepRequest BuildChain(int depth, bool safe)
    {
        var root = new DeepRequest { Value = "Safe Root" };
        var current = root;

        for (int i = 0; i < depth; i++)
        {
            current.Next = new DeepRequest();
            current = current.Next;

            // INJECTION POINT: No meio do caminho (Nível 7)
            if (!safe && i == 14)
            {
                current.Value = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('THM')//>\\x3e"; // ☠️ DEADLY
            }
            else
            {
                current.Value = $"Safe Level {i}";
            }
        }
        return root;
    }

    // --- HAPPY PATH (Scanning Clean Data) ---

    [Benchmark]
    [BenchmarkCategory("Clean")]
    public async Task Reflection_Clean_Scan()
    {
        await _reflectionInterceptor.UnaryServerHandler(
            _cleanRequest, _context, (r, c) => _cachedResponse).ConfigureAwait(false);
    }

    [Benchmark]
    [BenchmarkCategory("Clean")]
    public async Task SourceGen_Clean_Scan()
    {
        await _sourceGenInterceptor.UnaryServerHandler(
            _cleanRequest, _context, (r, c) => _cachedResponse).ConfigureAwait(false);
    }

    // --- ATTACK PATH (Detect & Block) ---

    [Benchmark]
    [BenchmarkCategory("Attack")]
    public async Task Reflection_Block_Attack()
    {
        try
        {
            await _reflectionInterceptor.UnaryServerHandler(
                _infectedRequest, _context, (r, c) => _cachedResponse).ConfigureAwait(false);
        }
        catch (RpcException)
        {
            // Expected: Security Exception caught here
        }
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Attack")]
    public async Task SourceGen_Block_Attack()
    {
        try
        {
            await _sourceGenInterceptor.UnaryServerHandler(
                _infectedRequest, _context, (r, c) => _cachedResponse).ConfigureAwait(false);
        }
        catch (RpcException)
        {
            // Expected: Security Exception caught here
        }
    }
}

// STUBS NECESSÁRIOS (Mantenha no final do arquivo)

// public partial class DeepTargetService : Library.LibraryBase
// {
//     public override Task<DeepRequest> DeepOperation(DeepRequest request, ServerCallContext context)
//         => Task.FromResult(request);
// }

public class FakeServerCallContext : ServerCallContext
{
    private readonly string _methodName;
    public FakeServerCallContext(string methodName) => _methodName = methodName;
    protected override string MethodCore => _methodName;
    protected override string HostCore => "localhost";
    protected override string PeerCore => "127.0.0.1";
    protected override DateTime DeadlineCore => DateTime.MaxValue;
    protected override Metadata RequestHeadersCore => Metadata.Empty;
    protected override CancellationToken CancellationTokenCore => CancellationToken.None;
    protected override Metadata ResponseTrailersCore => Metadata.Empty;
    protected override Status StatusCore { get; set; }
    protected override WriteOptions? WriteOptionsCore { get; set; }
    protected override AuthContext AuthContextCore => null!;
    protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) => throw new NotImplementedException();
    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
}