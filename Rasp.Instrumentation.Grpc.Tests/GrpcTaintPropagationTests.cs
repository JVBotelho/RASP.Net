using System;
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
/// Verifies taint marking against the REAL registered production interceptor
/// (the source-generated {Service}RaspInterceptor wired via AddRaspSecurity(), see
/// GrpcInterceptorTests's harness) - not SecurityInterceptor, which is a generic
/// fallback used only by benchmarks and never registered by AddRaspSecurity().
/// </summary>
public class TaintCheckingLibraryService : Library.LibraryBase
{
    public static bool? LastTitleWasTainted;

    public override Task<BookResponse> CreateBook(CreateBookRequest request, ServerCallContext context)
    {
        // Runs server-side, in-process (TestServer uses an in-memory transport) - by the
        // time this handler executes, the generated Validate_CreateBook has already run
        // (it's invoked from UnaryServerHandler before `continuation(request, context)`),
        // so this checks the exact same request.Title instance it should have marked.
        LastTitleWasTainted = RaspTaintSensor.IsTainted(request.Title);
        return Task.FromResult(new BookResponse { Id = 1, Title = request.Title });
    }
}

public class GrpcTaintPropagationTests : IAsyncLifetime
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
                    app.UseEndpoints(endpoints => endpoints.MapGrpcService<TaintCheckingLibraryService>());
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
    public async Task GeneratedInterceptor_MarksRequestStringFields_BeforeHandlerRuns()
    {
        TaintCheckingLibraryService.LastTitleWasTainted = null;

        await _client.CreateBookAsync(new CreateBookRequest
        {
            Title = "Some Title " + Guid.NewGuid(),
            Author = "Some Author"
        });

        Assert.True(TaintCheckingLibraryService.LastTitleWasTainted);
    }
}
