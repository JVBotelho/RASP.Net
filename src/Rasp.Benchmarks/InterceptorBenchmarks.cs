// using System.Diagnostics;
// using BenchmarkDotNet.Attributes;
// using BenchmarkDotNet.Configs;
// using Microsoft.Extensions.Logging.Abstractions;
// using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Options;
// using Rasp.Core.Abstractions;
// using Rasp.Core.Engine;
// using Rasp.Core.Models;
// using Rasp.Core.Configuration;
// using Rasp.Core.Enums;
// using Rasp.Instrumentation.Grpc.Interceptors;
// using Grpc.Core;
// using LibrarySystem.Contracts.Protos;
// using Google.Protobuf;
//
// namespace Rasp.Benchmarks;
//
// // Implementação No-Op atualizada para a nova interface
// public class NoOpDetectionEngine : IDetectionEngine
// {
//     public DetectionResult Inspect(string? payload, string context = "Unknown") => DetectionResult.Safe();
//     public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown") => DetectionResult.Safe();
// }
//
// // Simulador do inspetor gerado (para testar o throughput do interceptor e da engine, não do gerador em si)
// public class BenchmarkGrpcInspector : IGrpcMessageInspector
// {
//     public DetectionResult Inspect(IMessage message, IDetectionEngine engine, int maxScanChars)
//     {
//         ArgumentNullException.ThrowIfNull(engine);
//         
//         if (message is CreateBookRequest req)
//         {
//             // Simulação justa: O código gerado verifica Title e Author.
//             // Aqui fazemos o mesmo usando a engine genérica.
//             
//             // 1. Title Scan
//             if (!string.IsNullOrEmpty(req.Title))
//             {
//                 // FIX: Usamos "Title" como contexto para forçar o modo estrito (Bloqueio real)
//                 var res = engine.Inspect(req.Title.AsSpan(), "Unknown");
//                 if (res.IsThreat) return res;
//             }
//             
//             // 2. Author Scan
//             if (!string.IsNullOrEmpty(req.Author))
//             {
//                 var res = engine.Inspect(req.Author.AsSpan(), "Unknown");
//                 if (res.IsThreat) return res;
//             }
//         }
//         return DetectionResult.Safe();
//     }
// }
//
// public class FakeServerCallContext2 : ServerCallContext
// {
//     protected override string MethodCore => "/Library/CreateBook";
//     protected override string HostCore => "localhost";
//     protected override string PeerCore => "ipv4:127.0.0.1:5555";
//     protected override DateTime DeadlineCore => DateTime.MaxValue;
//     protected override Metadata RequestHeadersCore => Metadata.Empty;
//     protected override CancellationToken CancellationTokenCore => CancellationToken.None;
//     protected override Metadata ResponseTrailersCore => Metadata.Empty;
//     protected override Status StatusCore { get; set; }
//     protected override WriteOptions? WriteOptionsCore { get; set; }
//     protected override AuthContext AuthContextCore => null!;
//
//     protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options)
//         => throw new NotImplementedException();
//
//     protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders)
//         => Task.CompletedTask;
// }
//
// [MemoryDiagnoser]
// [RankColumn]
// [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
// public class InterceptorBenchmarks
// {
//     private SecurityInterceptor _realInterceptor = null!;
//     private SecurityInterceptor _baselineInterceptor = null!;
//     private readonly FakeServerCallContext2 _context = new();
//
//     private CreateBookRequest _safeRequest = null!;
//     private CreateBookRequest _sqliRequest = null!;
//     private CreateBookRequest _xssRequest = null!;
//
//     private UnaryServerMethod<CreateBookRequest, BookResponse> _continuationDelegate = null!;
//
//     [Params(100, 1000, 10000)]
//     public int PayloadSize { get; set; }
//
//     [GlobalSetup]
//     public void Setup()
//     {
//         var loggerFactory = NullLoggerFactory.Instance;
//
//         // Setup Engines Reais
//         var sqlEngine = new SqlInjectionDetectionEngine(NullLogger<SqlInjectionDetectionEngine>.Instance);
//         var xssEngine = new XssDetectionEngine(NullLogger<XssDetectionEngine>.Instance);
//         
//         // Composite: O Genérico usa isso para rodar SQL + XSS em uma chamada
//         var compositeEngine = new CompositeDetectionEngine(sqlEngine, xssEngine);
//         
//         var noOpEngine = new NoOpDetectionEngine();
//         var inspector = new BenchmarkGrpcInspector();
//         var options = Options.Create(new RaspOptions { MaxGrpcScanChars = 1024 * 1024 }); 
//         var interceptorLogger = NullLogger<SecurityInterceptor>.Instance;
//
//         // Warmup
//         compositeEngine.Inspect("warmup ' OR 1=1", "warmup");
//         compositeEngine.Inspect("<script>alert(1)</script>", "warmup");
//
//         // Inicializa Interceptors
//         _realInterceptor = new SecurityInterceptor(compositeEngine, inspector, options, interceptorLogger);
//         _baselineInterceptor = new SecurityInterceptor(noOpEngine, inspector, options, interceptorLogger);
//
//         // Payloads
//         var longString = new string('a', PayloadSize);
//
//         _safeRequest = new CreateBookRequest
//         {
//             Title = "Clean Code: " + longString,
//             Author = "Robert C. Martin",
//             PublicationYear = 2008
//         };
//
//         _sqliRequest = new CreateBookRequest
//         {
//             Title = "SQLi Attempt",
//             Author = longString + "' UNION SELECT 1, @@version -- " // SQLi no Author
//         };
//
//         _xssRequest = new CreateBookRequest
//         {
//             Title = "XSS <script>alert(1)</script>", // XSS no Title
//             Author = longString
//         };
//
//         _continuationDelegate = (req, ctx) => Task.FromResult(new BookResponse { Id = 1 });
//     }
//
//     [Benchmark(Baseline = true)]
//     [BenchmarkCategory("Overhead")]
//     public async Task<BookResponse> Baseline_NoOp()
//     {
//         return await _baselineInterceptor.UnaryServerHandler(
//             _safeRequest,
//             _context,
//             _continuationDelegate).ConfigureAwait(false);
//     }
//
//     [Benchmark]
//     [BenchmarkCategory("Overhead")]
//     public async Task<BookResponse> RASP_Safe_Traffic()
//     {
//         return await _realInterceptor.UnaryServerHandler(
//             _safeRequest,
//             _context,
//             _continuationDelegate).ConfigureAwait(false);
//     }
//
//     [Benchmark]
//     [BenchmarkCategory("Protection")]
//     public async Task RASP_Block_SQLi()
//     {
//         try
//         {
//             await _realInterceptor.UnaryServerHandler(
//                 _sqliRequest,
//                 _context,
//                 _continuationDelegate).ConfigureAwait(false);
//         }
//         catch (RpcException)
//         {
//             // Expected block
//         }
//     }
//
//     [Benchmark]
//     [BenchmarkCategory("Protection")]
//     public async Task RASP_Block_XSS()
//     {
//         try
//         {
//             await _realInterceptor.UnaryServerHandler(
//                 _xssRequest,
//                 _context,
//                 _continuationDelegate).ConfigureAwait(false);
//         }
//         catch (RpcException)
//         {
//             // Expected block
//         }
//     }
// }