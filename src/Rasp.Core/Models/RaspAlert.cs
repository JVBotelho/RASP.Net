namespace Rasp.Core.Models;

/// <summary>
/// Reusable Alert DTO. Mutable for Object Pooling.
/// </summary>
public sealed class RaspAlert
{
    public string ThreatType { get; set; } = string.Empty;
    public string PayloadSnippet { get; set; } = string.Empty;
    public string Context { get; set; } = string.Empty; // Legacy / Sink Identity
    public string? CorrelationId { get; set; }
    public string? Source { get; set; }
    public string? RemoteId { get; set; }
    public string? TraceId { get; set; }
    public DateTime Timestamp { get; set; }

    public void Reset()
    {
        ThreatType = string.Empty;
        PayloadSnippet = string.Empty;
        Context = string.Empty;
        CorrelationId = null;
        Source = null;
        RemoteId = null;
        TraceId = null;
        Timestamp = default;
    }
}