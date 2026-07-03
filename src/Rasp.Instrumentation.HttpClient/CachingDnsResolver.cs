using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;

namespace Rasp.Instrumentation.HttpClient;

/// <summary>
/// Decorates an <see cref="IDnsResolver"/> with an optional, opt-in TTL cache
/// (<see cref="RaspOptions.SsrfDnsCacheDuration"/>). Disabled by default - see that option's
/// doc comment for the DNS-rebinding tradeoff this makes when enabled. Public so callers can
/// construct their own resolution pipeline (e.g. wrapping a decorator other than
/// <see cref="SystemDnsResolver"/>) instead of relying solely on <c>AddRaspHttpClient()</c>'s
/// default wiring.
/// </summary>
public sealed class CachingDnsResolver : IDnsResolver
{
    // Bounds worst-case memory if this is ever pointed at attacker-influenceable hostnames
    // despite the option's own warning against exactly that. Deliberately simple, not an
    // LRU: once full, resolutions for a NEW host just stop being cached (degrades to
    // always-resolve for the overflow, not unbounded growth) rather than evicting an
    // existing entry - correctness for hosts already cached matters more here than
    // maximizing hit rate under pressure.
    private const int MaxCacheEntries = 1024;

    private readonly IDnsResolver _inner;
    private readonly IOptions<RaspOptions> _options;
    private readonly ConcurrentDictionary<string, (IPHostEntry Entry, long ExpiresAtTimestamp)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public CachingDnsResolver(IDnsResolver inner, IOptions<RaspOptions> options)
    {
        _inner = inner;
        _options = options;
    }

    public async Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress, CancellationToken cancellationToken)
    {
        var duration = _options.Value.SsrfDnsCacheDuration;
        if (duration <= TimeSpan.Zero)
        {
            return await _inner.GetHostEntryAsync(hostNameOrAddress, cancellationToken).ConfigureAwait(false);
        }

        var now = Stopwatch.GetTimestamp();
        if (_cache.TryGetValue(hostNameOrAddress, out var cached) && cached.ExpiresAtTimestamp > now)
        {
            return cached.Entry;
        }

        var entry = await _inner.GetHostEntryAsync(hostNameOrAddress, cancellationToken).ConfigureAwait(false);
        var expiresAt = now + (long)(duration.TotalSeconds * Stopwatch.Frequency);
        if (_cache.ContainsKey(hostNameOrAddress) || _cache.Count < MaxCacheEntries)
        {
            _cache[hostNameOrAddress] = (entry, expiresAt);
        }

        return entry;
    }
}
