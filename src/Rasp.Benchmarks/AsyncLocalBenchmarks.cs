using System;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Rasp.Core.Context;

namespace Rasp.Benchmarks;

[MemoryDiagnoser]
public class AsyncLocalBenchmarks
{
    private RaspContext _dummyContext = default!;

    [GlobalSetup]
    public void Setup()
    {
        _dummyContext = new RaspContext
        {
            CorrelationId = Guid.NewGuid().ToString("N"),
            Source = "Benchmark Source",
            StartedUtc = DateTime.UtcNow
        };
    }

    [Benchmark(Baseline = true)]
    public async Task Baseline_NoContext()
    {
        // Simulate a request with multiple async hops
        await AwaitHop1().ConfigureAwait(false);
    }

    [Benchmark]
    public async Task WithContext_Active()
    {
        using var scope = RaspExecutionContext.BeginScope(_dummyContext);
        await AwaitHop1().ConfigureAwait(false);

        // Simulate a read at the sink
        var current = RaspExecutionContext.Current;
        if (current == null) throw new InvalidOperationException();
    }

    private async Task AwaitHop1()
    {
        await Task.Yield(); // Force suspension
        await AwaitHop2().ConfigureAwait(false);
    }

    private async Task AwaitHop2()
    {
        await Task.Yield();
        await AwaitHop3().ConfigureAwait(false);
    }

    private async Task AwaitHop3()
    {
        await Task.Yield();
        // end of chain
    }
}
