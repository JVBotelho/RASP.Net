using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Instrumentation.HttpClient;
using Xunit;

namespace Rasp.Instrumentation.HttpClient.Tests;

internal sealed class CountingDnsResolver : IDnsResolver
{
    public int CallCount { get; private set; }

    public Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress, CancellationToken cancellationToken)
    {
        CallCount++;
        return Task.FromResult(new IPHostEntry
        {
            HostName = hostNameOrAddress,
            AddressList = new[] { IPAddress.Parse("10.0.0.1") },
        });
    }
}

public class CachingDnsResolverTests
{
    [Fact]
    public async Task Duration_Zero_NeverCaches()
    {
        var inner = new CountingDnsResolver();
        var options = Options.Create(new RaspOptions { SsrfDnsCacheDuration = TimeSpan.Zero });
        var resolver = new CachingDnsResolver(inner, options);

        await resolver.GetHostEntryAsync("example.com", CancellationToken.None);
        await resolver.GetHostEntryAsync("example.com", CancellationToken.None);

        inner.CallCount.Should().Be(2);
    }

    [Fact]
    public async Task WithinTtl_ReusesCachedEntry()
    {
        var inner = new CountingDnsResolver();
        var options = Options.Create(new RaspOptions { SsrfDnsCacheDuration = TimeSpan.FromMinutes(5) });
        var resolver = new CachingDnsResolver(inner, options);

        var first = await resolver.GetHostEntryAsync("example.com", CancellationToken.None);
        var second = await resolver.GetHostEntryAsync("example.com", CancellationToken.None);

        inner.CallCount.Should().Be(1);
        second.Should().BeSameAs(first);
    }

    [Fact]
    public async Task IsCaseInsensitive()
    {
        var inner = new CountingDnsResolver();
        var options = Options.Create(new RaspOptions { SsrfDnsCacheDuration = TimeSpan.FromMinutes(5) });
        var resolver = new CachingDnsResolver(inner, options);

        await resolver.GetHostEntryAsync("Example.com", CancellationToken.None);
        await resolver.GetHostEntryAsync("example.COM", CancellationToken.None);

        inner.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task AfterTtlExpires_ReResolves()
    {
        var inner = new CountingDnsResolver();
        var options = Options.Create(new RaspOptions { SsrfDnsCacheDuration = TimeSpan.FromMilliseconds(50) });
        var resolver = new CachingDnsResolver(inner, options);

        await resolver.GetHostEntryAsync("example.com", CancellationToken.None);
        await Task.Delay(150);
        await resolver.GetHostEntryAsync("example.com", CancellationToken.None);

        inner.CallCount.Should().Be(2);
    }

    [Fact]
    public async Task DifferentHosts_CachedIndependently()
    {
        var inner = new CountingDnsResolver();
        var options = Options.Create(new RaspOptions { SsrfDnsCacheDuration = TimeSpan.FromMinutes(5) });
        var resolver = new CachingDnsResolver(inner, options);

        await resolver.GetHostEntryAsync("a.example.com", CancellationToken.None);
        await resolver.GetHostEntryAsync("b.example.com", CancellationToken.None);

        inner.CallCount.Should().Be(2);
    }

    [Fact]
    public async Task CacheIsBounded_OverflowHostsDoNotStopBeingCached_ButEarlyEntriesSurvive()
    {
        const int maxCacheEntries = 1024;
        var inner = new CountingDnsResolver();
        var options = Options.Create(new RaspOptions { SsrfDnsCacheDuration = TimeSpan.FromMinutes(5) });
        var resolver = new CachingDnsResolver(inner, options);

        for (int i = 0; i < maxCacheEntries; i++)
        {
            await resolver.GetHostEntryAsync($"host{i}.example.com", CancellationToken.None);
        }

        var callsAfterFilling = inner.CallCount;

        // An early entry is still cached - the bound doesn't evict what's already there.
        await resolver.GetHostEntryAsync("host0.example.com", CancellationToken.None);
        inner.CallCount.Should().Be(callsAfterFilling);

        // A host beyond capacity isn't cached at all - each lookup re-resolves.
        await resolver.GetHostEntryAsync("overflow.example.com", CancellationToken.None);
        await resolver.GetHostEntryAsync("overflow.example.com", CancellationToken.None);
        inner.CallCount.Should().Be(callsAfterFilling + 2);
    }
}
