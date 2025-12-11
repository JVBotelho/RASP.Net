using System.Diagnostics;
using System.Diagnostics.Metrics;
using Rasp.Core.Abstractions;

namespace Rasp.Core.Telemetry;

/// <summary>
/// Native .NET implementation of RASP telemetry using System.Diagnostics.Metrics.
/// Designed for zero-allocation in hot paths where possible.
/// </summary>
public sealed class RaspMetrics : IRaspMetrics
{
    public const string MeterName = "Rasp.Net";

    private readonly Counter<long> _inspectionsCounter;
    private readonly Counter<long> _threatsCounter;
    private readonly Histogram<double> _durationHistogram;

    public RaspMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName, "1.0.0");

        _inspectionsCounter = meter.CreateCounter<long>(
            "rasp.inspections.total",
            description: "Total number of RASP inspections performed");

        _threatsCounter = meter.CreateCounter<long>(
            "rasp.threats.total",
            description: "Total number of threats detected or blocked");

        _durationHistogram = meter.CreateHistogram<double>(
            "rasp.inspection.duration",
            unit: "ms",
            description: "Distribution of time taken to inspect requests");
    }

    public void RecordInspection(string layer, double durationMs)
    {
        TagList tags = new TagList
        {
            { "layer", layer }
        };

        _inspectionsCounter.Add(1, tags);
        _durationHistogram.Record(durationMs, tags);
    }

    public void ReportThreat(string layer, string threatType, bool blocked)
    {
        TagList tags = new TagList
        {
            { "layer", layer },
            { "threat_type", threatType },
            { "action", blocked ? "blocked" : "monitored" }
        };

        _threatsCounter.Add(1, tags);
    }
}