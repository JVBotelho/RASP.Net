using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rasp.Core;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Instrumentation.HttpClient;

namespace Rasp.Benchmarks;

internal sealed class BenchmarkMockPrimaryHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
}

// Runs a GET through the real RaspHttpClientBuilderFilter -> RaspHttpMessageHandler ->
// SsrfGuard pipeline (Hooked) vs. a plain HttpClient with no RASP filter registered
// (NoHook). Both terminate at BenchmarkMockPrimaryHandler so no real network I/O
// is involved - this isolates the SSRF guard's own CPU/allocation overhead.
[MemoryDiagnoser]
public class SsrfBenchmarks
{
    private static readonly Uri SafeUrl = new("https://www.example.com/books");

    private System.Net.Http.HttpClient _hookedClient = null!;
    private System.Net.Http.HttpClient _plainClient = null!;

    [GlobalSetup]
    public void Setup()
    {
        var hookedServices = new ServiceCollection();
        hookedServices.Configure<RaspOptions>(opt => opt.BlockOnSsrfDetection = true);
        hookedServices.AddSingleton<IRaspMetrics, DummyMetrics>();
        hookedServices.AddLogging();
        hookedServices.AddRaspHttpClient();
        hookedServices.AddHttpClient("Hooked")
            .ConfigurePrimaryHttpMessageHandler(() => new BenchmarkMockPrimaryHandler());
        var hookedProvider = hookedServices.BuildServiceProvider();
        _hookedClient = hookedProvider.GetRequiredService<IHttpClientFactory>().CreateClient("Hooked");

        var plainServices = new ServiceCollection();
        plainServices.AddHttpClient("Plain")
            .ConfigurePrimaryHttpMessageHandler(() => new BenchmarkMockPrimaryHandler());
        var plainProvider = plainServices.BuildServiceProvider();
        _plainClient = plainProvider.GetRequiredService<IHttpClientFactory>().CreateClient("Plain");
    }

    [Benchmark(Baseline = true)]
    public async Task NoHook_SafeRequest()
        => await _plainClient.GetAsync(SafeUrl).ConfigureAwait(false);

    [Benchmark]
    public async Task Hooked_SafeRequest()
        => await _hookedClient.GetAsync(SafeUrl).ConfigureAwait(false);
}
