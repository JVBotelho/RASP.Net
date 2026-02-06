// using System;
// using System.Buffers;
// using System.Threading;
// using System.Threading.Tasks;
// using BenchmarkDotNet.Attributes;
// using BenchmarkDotNet.Configs;
// using Grpc.Core;
// using Grpc.Core.Interceptors;
// using LibrarySystem.Contracts.Protos; 
// using Microsoft.Extensions.Logging.Abstractions;
// using Rasp.Core.Engine;
//
// namespace Rasp.Benchmarks;
//
// // 1. O GATILHO (Trigger)
// // Essa classe existe para o Source Generator identificar e criar o Interceptor.
// public partial class PerformanceTargetService : Library.LibraryBase
// {
//     public override Task<BookResponse> create_book(CreateBookRequest request, ServerCallContext context)
//         => Task.FromResult(new BookResponse());
//
//     public override Task<BookResponse> GetBookById(GetBookByIdRequest request, ServerCallContext context)
//         => Task.FromResult(new BookResponse());
// }
//
// // 2. O BENCHMARK
// [MemoryDiagnoser]
// [RankColumn]
// [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
// public class SourceGeneratorBenchmarks
// {
//     // O Interceptor gerado aparecerá aqui após um Build com sucesso
//     private Interceptor _generatedInterceptor = null!;
//     
//     // Contextos estáticos
//     private readonly FakeServerCallContext _createBookContext = new("/Library/CreateBook");
//     private readonly FakeServerCallContext _getBookContext = new("/Library/GetBookById");
//
//     // Payloads
//     private CreateBookRequest _safeRequest = null!;
//     private CreateBookRequest _xssRequest = null!;
//     private GetBookByIdRequest _fastRequest = null!;
//
//     // Continuation
//     private UnaryServerMethod<CreateBookRequest, BookResponse> _continuationCreate = null!;
//
//     [Params(100, 1000)]
//     public int PayloadSize { get; set; }
//
//     [GlobalSetup]
//     public void Setup()
//     {
//         // FIX: Uso direto do NullLogger tipado para evitar erro de compilação
//         var sqlLogger = NullLogger<SqlInjectionDetectionEngine>.Instance;
//         var xssLogger = NullLogger<XssDetectionEngine>.Instance;
//         
//         // Setup Real das Engines
//         var sqlEngine = new SqlInjectionDetectionEngine(sqlLogger);
//         var xssEngine = new XssDetectionEngine(xssLogger);
//
//         // Warmup JIT
//         xssEngine.Inspect("warmup", "warmup");
//         sqlEngine.Inspect("warmup", "warmup");
//
//         // INSTANCIAÇÃO DO CÓDIGO GERADO
//         // Se o seu IDE marcar isso como vermelho, ignore e rode o 'dotnet build'.
//         // O tipo é gerado durante a compilação.
//         _generatedInterceptor = new PerformanceTargetService_RaspInterceptor(sqlEngine, xssEngine);
//
//         // Preparar Carga
//         var longString = new string('a', PayloadSize);
//
//         _safeRequest = new CreateBookRequest
//         {
//             Title = "Clean Code " + longString,
//             Author = "Robert Martin",
//             PublicationYear = 2008
//         };
//
//         _xssRequest = new CreateBookRequest
//         {
//             Title = "Clean Code <script>alert(1)</script>",
//             Author = "Hacker",
//         };
//
//         _fastRequest = new GetBookByIdRequest { Id = 123 };
//
//         _continuationCreate = (req, ctx) => Task.FromResult(new BookResponse());
//     }
//
//     [Benchmark(Baseline = true)]
//     [BenchmarkCategory("HappyPath")]
//     public async Task<BookResponse> ZeroCost_IntegerOnly()
//     {
//         // Rota sem strings (GetBookById) -> Deve ser instantâneo
//         return await _generatedInterceptor.UnaryServerHandler(
//             _fastRequest,
//             _getBookContext, 
//             (req, ctx) => Task.FromResult(new BookResponse()) 
//         ).ConfigureAwait(false);
//     }
//
//     [Benchmark]
//     [BenchmarkCategory("HappyPath")]
//     public async Task<BookResponse> Scan_String_Safe()
//     {
//         // Rota com strings (CreateBook) -> Passa pelo Engine
//         return await _generatedInterceptor.UnaryServerHandler(
//             _safeRequest,
//             _createBookContext,
//             _continuationCreate
//         ).ConfigureAwait(false);
//     }
//
//     [Benchmark]
//     [BenchmarkCategory("Attack")]
//     public async Task Block_XSS()
//     {
//         try
//         {
//             // Rota com ataque -> Bloqueia e lança Exceção
//             await _generatedInterceptor.UnaryServerHandler(
//                 _xssRequest,
//                 _createBookContext,
//                 _continuationCreate
//             ).ConfigureAwait(false);
//         }
//         catch (RpcException)
//         {
//             // Expected
//         }
//     }
// }
//
// // 3. MOCK DO CONTEXTO
// public class FakeServerCallContext : ServerCallContext
// {
//     private readonly string _methodName;
//     public FakeServerCallContext(string methodName) => _methodName = methodName;
//
//     protected override string MethodCore => _methodName;
//     protected override string HostCore => "localhost";
//     protected override string PeerCore => "127.0.0.1";
//     protected override DateTime DeadlineCore => DateTime.MaxValue;
//     protected override Metadata RequestHeadersCore => Metadata.Empty;
//     protected override CancellationToken CancellationTokenCore => CancellationToken.None;
//     protected override Metadata ResponseTrailersCore => Metadata.Empty;
//     protected override Status StatusCore { get; set; }
//     protected override WriteOptions? WriteOptionsCore { get; set; }
//     protected override AuthContext AuthContextCore => null!; // Fix: Retorna null em vez de lançar exceção
//     protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) 
//         => throw new NotImplementedException();
//     protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) 
//         => Task.CompletedTask;
// }