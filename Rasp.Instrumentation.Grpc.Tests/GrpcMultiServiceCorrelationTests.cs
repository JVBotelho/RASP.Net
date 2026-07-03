using System;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Net.Client;
using LibrarySystem.Contracts.Protos;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Rasp.Bootstrapper;
using Rasp.Core.Configuration;
using Rasp.Core.Context;
using Rasp.Core.Infrastructure;
using Xunit;

namespace Rasp.Instrumentation.Grpc.Tests;

/// <summary>
/// AddRaspSecurity() registers one generated interceptor PER gRPC service compiled into the
/// assembly into the SAME global GrpcServiceOptions.Interceptors pipeline - this test project
/// already compiles two (Library, from LibrarySystem.Contracts, and ComplexTestService, from
/// Protos/test.proto), so every call here already passes through both interceptors nested,
/// regardless of which one is actually mapped as an endpoint. Before the RaspExecutionContext.Current
/// null-check guard in the generated UnaryServerHandler, each nested interceptor unconditionally
/// created its own RaspContext/CorrelationId, so the perimeter alert (pushed by whichever
/// interceptor's switch matched the request) and the RaspExecutionContext.Current the real
/// handler/sink observes (set by whichever interceptor is innermost) could carry different
/// CorrelationIds - defeating the source-to-sink join that's ADR 007's entire point.
/// GrpcCorrelationTests only asserts a context exists, not that its id matches the perimeter
/// alert's, so it didn't catch this; this test asserts the actual join.
/// </summary>
public class MultiServiceCorrelationLibraryService : Library.LibraryBase
{
    public static string? ObservedCorrelationId;

    public override Task<BookResponse> CreateBook(CreateBookRequest request, ServerCallContext context)
    {
        ObservedCorrelationId = RaspExecutionContext.Current?.CorrelationId;
        return Task.FromResult(new BookResponse { Id = 1, Title = request.Title });
    }
}

public class GrpcMultiServiceCorrelationTests : IAsyncLifetime
{
    private IHost _host = null!;
    private Library.LibraryClient _client = null!;
    private RaspAlertBus _bus = null!;

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
                    // Audit mode: the request must reach the handler (not be rejected) so we can
                    // compare the perimeter alert's CorrelationId against what the handler observes.
                    services.Configure<RaspOptions>(opt => opt.BlockOnDetection = false);
                    services.AddGrpc(options => { }).AddRaspSecurity();
                    // RaspAlertBus's channel is SingleReader=true, but AddRasp() also starts
                    // RaspAlertConsumerService (a BackgroundService that drains the same channel
                    // to structured-log alerts). This test needs to be the sole reader to
                    // deterministically observe the alert its own request produces, so the
                    // built-in consumer is removed here rather than raced against.
                    services.RemoveAll<Microsoft.Extensions.Hosting.IHostedService>();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapGrpcService<MultiServiceCorrelationLibraryService>());
                });
            })
            .StartAsync();

        _bus = _host.Services.GetRequiredService<RaspAlertBus>();
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
    public async Task PerimeterAlert_AndSinkObservedContext_ShareCorrelationId_WithMultipleInterceptorsRegistered()
    {
        MultiServiceCorrelationLibraryService.ObservedCorrelationId = null;

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var enumerator = _bus.ReadAlertsAsync(cts.Token).GetAsyncEnumerator(cts.Token);

        await _client.CreateBookAsync(new CreateBookRequest
        {
            Title = "<script>alert(1)</script>",
            Author = "Attacker"
        });

        Assert.True(await enumerator.MoveNextAsync());
        var alert = enumerator.Current;

        Assert.NotNull(alert.CorrelationId);
        Assert.NotNull(MultiServiceCorrelationLibraryService.ObservedCorrelationId);
        Assert.Equal(alert.CorrelationId, MultiServiceCorrelationLibraryService.ObservedCorrelationId);
    }
}
