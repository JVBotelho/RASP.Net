namespace Rasp.Core.Models;

/// <summary>
/// Reusable Alert DTO. Mutable for Object Pooling.
/// </summary>
public sealed class RaspAlert
{
    public string ThreatType { get; set; } = string.Empty;
    public string PayloadSnippet { get; set; } = string.Empty;
    public string Context { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }

    public void Reset()
    {
        ThreatType = string.Empty;
        PayloadSnippet = string.Empty;
        Context = string.Empty;
        Timestamp = default;
    }
}