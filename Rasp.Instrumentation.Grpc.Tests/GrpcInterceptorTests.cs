using System;
using System.Threading.Tasks;
using System.Diagnostics.Metrics;
using System.Threading;
using FluentAssertions;
using Grpc.Core;
using Grpc.Net.Client;
using LibrarySystem.Contracts.Protos;
using Rasp.Instrumentation.Grpc.Tests.Protos;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rasp.Bootstrapper;
using Rasp.Core.Configuration;
using Rasp.Core.Infrastructure;
using Xunit;
using Microsoft.Extensions.Options;

namespace Rasp.Instrumentation.Grpc.Tests;

public class TestLibraryService : Library.LibraryBase
{
    public override Task<BookResponse> CreateBook(CreateBookRequest request, ServerCallContext context)
    {
        return Task.FromResult(new BookResponse { Id = 1, Title = request.Title });
    }
}

public class TestComplexService : ComplexTestService.ComplexTestServiceBase
{
    public override Task<ComplexResponse> SendComplex(ComplexRequest request, ServerCallContext context)
    {
        return Task.FromResult(new ComplexResponse { Success = true });
    }
}

public class TestLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
{
    public System.Collections.Generic.List<string> Logs { get; } = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

    public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        Logs.Add(formatter(state, exception));
    }
}

public class GrpcInterceptorTests : IAsyncLifetime
{
    private IHost _host = null!;
    private Library.LibraryClient _client = null!;
    private ComplexTestService.ComplexTestServiceClient _complexClient = null!;
    private IServiceProvider _services = null!;

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

                    // We test that AddRasp provides IRaspMetrics, so no AddSingleton<IRaspMetrics> here!
                    services.PostConfigure<RaspOptions>(opt => 
                    {
                        opt.BlockOnDetection = true; 
                        opt.EnableMetrics = true;
                    });
                    
                    services.AddGrpc(options => { }).AddRaspSecurity();
                });

                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGrpcService<TestLibraryService>();
                        endpoints.MapGrpcService<TestComplexService>();
                    });
                });
            })
            .StartAsync();

        _services = _host.Services;
        var handler = _host.GetTestServer().CreateHandler();
        var channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions { HttpHandler = handler });
        _client = new Library.LibraryClient(channel);
        _complexClient = new ComplexTestService.ComplexTestServiceClient(channel);
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
    }

    [Fact]
    public async Task SafeRequest_ShouldReturnSuccessfully()
    {
        var response = await _client.CreateBookAsync(new CreateBookRequest
        {
            Title = "Clean Code",
            Author = "Robert C. Martin",
            PublicationYear = 2008
        });

        response.Title.Should().Be("Clean Code");
    }

    [Fact]
    public async Task SqliRequest_ShouldBeBlocked()
    {
        var exception = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            await _client.CreateBookAsync(new CreateBookRequest
            {
                Title = "SQLi Attempt",
                Author = "' UNION SELECT 1, @@version --"
            });
        });

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().Contain("RASP Security Violation");
    }

    [Fact]
    public async Task RepeatedFields_ShouldBeBlocked()
    {
        var exception = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            var req = new ComplexRequest();
            req.Tags.Add("safe");
            req.Tags.Add("<script>alert(1)</script>");

            await _complexClient.SendComplexAsync(req);
        });

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().Contain("RASP Security Violation");
    }

    [Fact]
    public async Task NestedFields_ShouldBeBlocked()
    {
        var exception = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            var req = new ComplexRequest
            {
                Nested = new NestedMessage { InternalNotes = "' OR 1=1 --" }
            };

            await _complexClient.SendComplexAsync(req);
        });

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().Contain("RASP Security Violation");
    }

    [Fact]
    public async Task AuditMode_ShouldNotBlockButLog()
    {
        // Change option at runtime via singleton reflection/mock if it's singleton. 
        // Wait, options are captured at startup. So we need a new host for AuditMode,
        // or just rely on another test class. Let's create a separate host.
        using var auditHost = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddGrpc();
                    var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build();
                    services.AddRasp(config);
                    services.PostConfigure<RaspOptions>(opt => { opt.BlockOnDetection = false; });
                    // Replace the default logger for the consumer service
                    services.AddSingleton<Microsoft.Extensions.Logging.ILogger<RaspAlertConsumerService>>(new TestLogger<RaspAlertConsumerService>());
                    services.AddGrpc(options => { }).AddRaspSecurity();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapGrpcService<TestLibraryService>());
                });
            }).StartAsync();

        var channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions { HttpHandler = auditHost.GetTestServer().CreateHandler() });
        var client = new Library.LibraryClient(channel);

        // It should NOT throw
        var response = await client.CreateBookAsync(new CreateBookRequest
        {
            Title = "XSS <script>alert(1)</script>",
            Author = "Attacker"
        });

        response.Title.Should().Be("XSS <script>alert(1)</script>");
        
        // Check that RaspAlertConsumerService consumed the alert by looking at its logger
        var logger = (TestLogger<RaspAlertConsumerService>)auditHost.Services.GetRequiredService<Microsoft.Extensions.Logging.ILogger<RaspAlertConsumerService>>();
        
        // Give the background service a brief moment to process the queue
        await Task.Delay(200);
        
        logger.Logs.Should().Contain(log => log.Contains("XSS") && log.Contains("script"));
    }
    
    [Fact]
    public async Task ThreatCounter_ShouldIncrement()
    {
        var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == "Rasp.Net")
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };

        long threatsDetected = 0;
        meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "rasp.threats.total")
            {
                threatsDetected += measurement;
            }
        });
        meterListener.Start();

        var exception = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            await _client.CreateBookAsync(new CreateBookRequest
            {
                Title = "XSS <script>alert(1)</script>",
                Author = "Attacker"
            });
        });

        meterListener.RecordObservableInstruments();
        threatsDetected.Should().BeGreaterThan(0);
    }
}
