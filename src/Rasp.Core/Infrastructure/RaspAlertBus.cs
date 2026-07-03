using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Rasp.Core.Abstractions;
using Rasp.Core.Models;
using Rasp.Core.Context;

namespace Rasp.Core.Infrastructure;

/// <summary>
/// High-Throughput Event Bus with Integrated Object Pooling.
/// Zero-Allocation on the hot path (Attack Scenario).
/// </summary>
public class RaspAlertBus
{
    private readonly Channel<RaspAlert> _channel;
    private readonly ConcurrentQueue<RaspAlert> _pool = new();
    private const int MaxPoolSize = 1000;
    private long _droppedCount;

    public RaspAlertBus()
    {
        _channel = Channel.CreateBounded<RaspAlert>(new BoundedChannelOptions(5000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    }

    /// <summary>
    /// Gets the number of alerts dropped due to the channel being full.
    /// </summary>
    public long DroppedCount => Volatile.Read(ref _droppedCount);

    /// <summary>
    /// Hot Path: Rents an alert object, populates it, and pushes to channel.
    /// Allocates 0 bytes on heap (if pool is warm).
    /// </summary>
    public void PushAlert(string threatType, string payload, string context)
    {
        PushAlertInternal(null, threatType, payload, context);
    }

    /// <summary>
    /// Pushes an alert with the ambient RaspContext for request-level provenance.
    /// </summary>
    public void PushAlert(RaspContext? ambientContext, string threatType, string payload, string sinkIdentity)
    {
        PushAlertInternal(ambientContext, threatType, payload, sinkIdentity);
    }

    private void PushAlertInternal(RaspContext? ambientContext, string threatType, string payload, string contextString)
    {
        if (!_pool.TryDequeue(out var alert))
        {
            alert = new RaspAlert();
        }

        alert.ThreatType = threatType;
        alert.PayloadSnippet = string.IsNullOrEmpty(payload) ? string.Empty :
                               payload.Length > 64 ? string.Concat(payload.AsSpan(0, 64), "...") : payload;
        alert.Context = contextString;

        if (ambientContext != null)
        {
            alert.CorrelationId = ambientContext.CorrelationId;
            alert.Source = ambientContext.Source;
            alert.RemoteId = ambientContext.RemoteId;
            alert.TraceId = ambientContext.TraceId;
        }

        alert.Timestamp = DateTime.UtcNow;

        if (!_channel.Writer.TryWrite(alert))
        {
            Interlocked.Increment(ref _droppedCount);
            ReturnToPool(alert);
        }
    }

    public async IAsyncEnumerable<RaspAlertEvent> ReadAlertsAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var alert in _channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            // Snapshot fields before returning to pool to prevent Use-After-Return.
            var snapshot = new RaspAlertEvent(
                alert.ThreatType,
                alert.PayloadSnippet,
                alert.Context,
                alert.CorrelationId,
                alert.Source,
                alert.RemoteId,
                alert.TraceId,
                alert.Timestamp);

            ReturnToPool(alert);
            yield return snapshot;
        }
    }

    private void ReturnToPool(RaspAlert alert)
    {
        if (_pool.Count >= MaxPoolSize) return;
        alert.Reset();
        _pool.Enqueue(alert);
    }
}

public readonly record struct RaspAlertEvent(
    string ThreatType,
    string PayloadSnippet,
    string Context,
    string? CorrelationId,
    string? Source,
    string? RemoteId,
    string? TraceId,
    DateTime Timestamp);