using Rasp.Core.Models;

namespace Rasp.Core.Abstractions;

/// <summary>
/// Defines the contract for the core detection logic.
/// Implementations of this interface are responsible for analyzing payloads 
/// and determining if they contain malicious patterns (e.g., SQLi, XSS).
/// </summary>
public interface IDetectionEngine
{
    /// <summary>
    /// Analyzes a generic text payload for potential threats.
    /// This is the primary entry point for string-based inspections (gRPC fields, SQL queries).
    /// </summary>
    /// <param name="payload">The content to inspect (e.g., user input, SQL command text).</param>
    /// <param name="context">Optional context about the source (e.g., "gRPC.BookService/CreateBook").</param>
    /// <returns>A <see cref="DetectionResult"/> indicating the verdict.</returns>
    DetectionResult Inspect(string? payload, string context = "Unknown");
}