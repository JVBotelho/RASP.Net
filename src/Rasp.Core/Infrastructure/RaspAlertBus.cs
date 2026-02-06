using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Rasp.Core.Models;

namespace Rasp.Core.Infrastructure;

/// <summary>
/// High-Throughput Event Bus with Integrated Object Pooling.
/// Zero-Allocation on the hot path (Attack Scenario).
/// </summary>
public class RaspAlertBus
{
    private readonly Channel<RaspAlert> _channel = Channel.CreateBounded<RaspAlert>(new BoundedChannelOptions(5000)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
        SingleWriter = false
    });

    private readonly ConcurrentQueue<RaspAlert> _pool = new();
    private const int MaxPoolSize = 1000;

    /// <summary>
    /// Hot Path: Rents an alert object, populates it, and pushes to channel.
    /// Allocates 0 bytes on heap (if pool is warm).
    /// </summary>
    public void PushAlert(string threatType, string payload, string context)
    {
        if (!_pool.TryDequeue(out var alert))
        {
            alert = new RaspAlert();
        }

        alert.ThreatType = threatType;
        alert.PayloadSnippet = payload;
        alert.Context = context;
        alert.Timestamp = DateTime.UtcNow;

        if (!_channel.Writer.TryWrite(alert))
        {
            ReturnToPool(alert);
        }
    }

    public async IAsyncEnumerable<RaspAlert> ReadAlertsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var alert in _channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            yield return alert;
            ReturnToPool(alert);
        }
    }

    private void ReturnToPool(RaspAlert alert)
    {
        if (_pool.Count >= MaxPoolSize) return;
        alert.Reset();
        _pool.Enqueue(alert);
    }
}