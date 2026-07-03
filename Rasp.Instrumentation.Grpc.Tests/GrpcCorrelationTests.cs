using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Net.Client;
using LibrarySystem.Contracts.Protos;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rasp.Bootstrapper;
using Rasp.Core.Context;
using Xunit;

namespace Rasp.Instrumentation.Grpc.Tests;

/// <summary>
/// Verifies the real production interceptor (the source-generated
/// {Service}RaspInterceptor, wired via AddRaspSecurity()) establishes a RaspContext -
/// ADR 007's whole point is that sink alerts are joinable back to the originating request,
/// which only holds if the perimeter that receives the request actually calls
/// RaspExecutionContext.BeginScope. Without this, every gRPC-originated sink alert
/// synthesizes an orphan context instead of a real one.
/// </summary>
public class CorrelationCheckingLibraryService : Library.LibraryBase
{
    public static RaspContext? ObservedContext;

    public override Task<BookResponse> CreateBook(CreateBookRequest request, ServerCallContext context)
    {
        ObservedContext = RaspExecutionContext.Current;
        return Task.FromResult(new BookResponse { Id = 1, Title = request.Title });
    }
}

public class GrpcCorrelationTests : IAsyncLifetime
{
    private IHost _host = null!;
    private Library.LibraryClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddGrpc();
                    var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build();
                    services.AddRasp(config);
                    services.AddGrpc(options => { }).AddRaspSecurity();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapGrpcService<CorrelationCheckingLibraryService>());
                });
            })
            .StartAsync();

        var handler = _host.GetTestServer().CreateHandler();
        var channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions { HttpHandler = handler });
        _client = new Library.LibraryClient(channel);
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
    }

    [Fact]
    public async Task GeneratedInterceptor_EstablishesRaspContext_BeforeHandlerRuns()
    {
        CorrelationCheckingLibraryService.ObservedContext = null;

        await _client.CreateBookAsync(new CreateBookRequest { Title = "Clean Code", Author = "Robert Martin" });

        var observed = CorrelationCheckingLibraryService.ObservedContext;
        Assert.NotNull(observed);
        Assert.False(string.IsNullOrEmpty(observed!.CorrelationId));
        Assert.StartsWith("gRPC ", observed.Source);
        Assert.Contains("CreateBook", observed.Source);
    }

    [Fact]
    public async Task GeneratedInterceptor_UsesDistinctCorrelationId_PerRequest()
    {
        CorrelationCheckingLibraryService.ObservedContext = null;
        await _client.CreateBookAsync(new CreateBookRequest { Title = "First", Author = "A" });
        var first = CorrelationCheckingLibraryService.ObservedContext;

        CorrelationCheckingLibraryService.ObservedContext = null;
        await _client.CreateBookAsync(new CreateBookRequest { Title = "Second", Author = "B" });
        var second = CorrelationCheckingLibraryService.ObservedContext;

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotEqual(first!.CorrelationId, second!.CorrelationId);
    }
}
