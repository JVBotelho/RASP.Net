namespace Rasp.Core.Abstractions;

/// <summary>
/// Defines the observability contract for the RASP engine.
/// Follows the "Red Team" principle: If it's not logged, it didn't happen.
/// </summary>
public interface IRaspMetrics
{
    /// <summary>
    /// Records the execution time of a security inspection.
    /// Critical for monitoring performance overhead (latency).
    /// </summary>
    /// <param name="layer">The layer being inspected (e.g., "gRPC", "EF Core").</param>
    /// <param name="durationMs">Time elapsed in milliseconds.</param>
    void RecordInspection(string layer, double durationMs);

    /// <summary>
    /// Reports a detected or blocked threat.
    /// </summary>
    /// <param name="layer">The layer where the threat was found.</param>
    /// <param name="threatType">The classification (e.g., "SQLi", "XSS").</param>
    /// <param name="blocked">True if the request was terminated; false if monitored only.</param>
    void ReportThreat(string layer, string threatType, bool blocked);
}