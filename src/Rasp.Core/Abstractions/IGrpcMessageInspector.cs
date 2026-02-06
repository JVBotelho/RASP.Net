using Google.Protobuf;
using Rasp.Core.Models;

namespace Rasp.Core.Abstractions;

/// <summary>
/// Contract for the compile-time generated Protobuf inspector.
/// <para>
/// This interface allows the runtime interceptor to invoke the generated static dispatch logic
/// without knowing the concrete types at compile time (Dependency Inversion).
/// </para>
/// </summary>
public interface IGrpcMessageInspector
{
    /// <summary>
    /// Inspects a Protobuf message for security threats using the generated static dispatch graph.
    /// </summary>
    /// <param name="message">The incoming or outgoing gRPC message.</param>
    /// <param name="engine">The active detection engine (SIMD/Zero-Alloc).</param>
    /// <param name="maxScanChars">
    /// The global inspection budget in characters (UTF-16).
    /// If the total inspection exceeds this limit, the inspector returns a DoS threat (Fail-Secure).
    /// </param>
    /// <returns>A DetectionResult indicating Safe or Threat.</returns>
    DetectionResult Inspect(IMessage message, IDetectionEngine engine, int maxScanChars);
}

/// <summary>
/// No-Op implementation used when no Protobuf messages are detected in the assembly
/// or when the Source Generator has not run yet.
/// </summary>
public class NoOpGrpcInspector : IGrpcMessageInspector
{
    public DetectionResult Inspect(IMessage message, IDetectionEngine engine, int maxScanChars)
        => DetectionResult.Safe();
}