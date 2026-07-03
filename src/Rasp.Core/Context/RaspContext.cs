using System;

namespace Rasp.Core.Context;

/// <summary>
/// Per-request ambient security context. Established at a source (gRPC/HTTP entrypoint),
/// flows with the logical call across async boundaries, and is read at every sink.
/// </summary>
public sealed class RaspContext
{
    /// <summary>Stable id correlating every source + sink event for one logical request.</summary>
    public required string CorrelationId { get; init; }

    /// <summary>The entrypoint that created this context, e.g. "gRPC BookService/CreateBook".</summary>
    public required string Source { get; init; }

    /// <summary>Transport-level origin where known (remote IP, user id, trace id).</summary>
    public string? RemoteId { get; init; }

    public string? TraceId { get; init; }

    /// <summary>When this request entered the protected boundary.</summary>
    public DateTime StartedUtc { get; init; }

    public override string ToString() => $"{Source} [{CorrelationId}]";
}
