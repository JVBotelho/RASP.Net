using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rasp.Core;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Exceptions;
using Rasp.Core.Infrastructure;
using Xunit;

namespace Rasp.Instrumentation.HttpClient.Tests;

public class DummyRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

public class RaspHttpClientTests
{
    private ServiceProvider CreateProvider(bool blockOnDetection = true)
    {
        var services = new ServiceCollection();

        services.Configure<RaspOptions>(opt =>
        {
            opt.BlockOnDetection = blockOnDetection;
            opt.BlockOnSsrfDetection = blockOnDetection;
            opt.BlockOnAdoNetDetection = blockOnDetection;
        });
        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        services.AddLogging();

        services.AddRaspCore();
        services.AddRaspHttpClient();

        if (!blockOnDetection)
        {
            // For audit mode test, use MockPrimaryHandler so it doesn't fail with real network error
            services.AddHttpClient("TestClient")
                    .ConfigurePrimaryHttpMessageHandler(() => new MockPrimaryHandler());
        }
        else
        {
            // For SSRF block tests, use real SocketsHttpHandler so ConnectCallback fires!
            services.AddHttpClient("TestClient")
                    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler());
        }

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task SafeRequest_ShouldProceedNormally()
    {
        // Use MockPrimaryHandler for safe request so we don't hit the network
        var services = new ServiceCollection();
        services.Configure<RaspOptions>(opt => opt.BlockOnSsrfDetection = true);
        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        services.AddLogging();
        services.AddRaspCore();
        services.AddRaspHttpClient();
        services.AddHttpClient("TestClient")
                .ConfigurePrimaryHttpMessageHandler(() => new MockPrimaryHandler());

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("TestClient");

        var response = await client.GetAsync("https://www.google.com");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Ssrf_Loopback_ShouldThrowRaspSecurityException()
    {
        var provider = CreateProvider(blockOnDetection: true);
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("TestClient");

        Func<Task> act = async () => await client.GetAsync("http://127.0.0.1/admin");

        await act.Should().ThrowAsync<RaspSecurityException>()
           .WithMessage("*Loopback*");
    }

    [Fact]
    public async Task Ssrf_Localhost_ShouldThrowRaspSecurityException_ViaConnectCallback()
    {
        var provider = CreateProvider(blockOnDetection: true);
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("TestClient");

        // "localhost" is a safe string in Layer 1, but resolves to 127.0.0.1/::1 in Layer 2 (ConnectCallback)
        Func<Task> act = async () => await client.GetAsync("http://localhost/admin");

        var ex = await act.Should().ThrowAsync<HttpRequestException>();
        ex.WithInnerException<RaspSecurityException>()
           .WithMessage("*Loopback*");
    }

    [Fact]
    public async Task Ssrf_CloudMetadata_ShouldThrowRaspSecurityException()
    {
        var provider = CreateProvider(blockOnDetection: true);
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("TestClient");

        Func<Task> act = async () => await client.GetAsync("http://169.254.169.254/latest/meta-data/");

        await act.Should().ThrowAsync<RaspSecurityException>()
           .WithMessage("*Cloud metadata*");
    }

    [Fact]
    public async Task Ssrf_FileScheme_ShouldThrowRaspSecurityException()
    {
        var provider = CreateProvider(blockOnDetection: true);
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("TestClient");

        Func<Task> act = async () => await client.GetAsync("file:///etc/passwd");

        await act.Should().ThrowAsync<RaspSecurityException>()
           .WithMessage("*Dangerous URI scheme*");
    }

    [Fact]
    public async Task Ssrf_AuditMode_ShouldNotThrow()
    {
        var provider = CreateProvider(blockOnDetection: false);
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("TestClient");

        Func<Task> act = async () => await client.GetAsync("http://169.254.169.254/latest/meta-data/");

        await act.Should().NotThrowAsync<RaspSecurityException>();
    }
}

internal class MockPrimaryHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
