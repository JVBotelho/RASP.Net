using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Rasp.Instrumentation.HttpClient;

/// <summary>
/// Seam over <see cref="System.Net.Dns"/> so the SSRF-guarded <see cref="RaspHttpClientBuilderFilter"/>
/// can be tested with a fixed, controlled resolution instead of the machine's real DNS/hosts behavior.
/// </summary>
public interface IDnsResolver
{
    Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress, CancellationToken cancellationToken);
}

/// <summary>
/// The default <see cref="IDnsResolver"/>, delegating to <see cref="System.Net.Dns"/>. Public so
/// callers can compose their own <see cref="IDnsResolver"/> decorators (e.g. a benchmark harness
/// simulating realistic DNS RTT) around it, the same way <see cref="CachingDnsResolver"/> does.
/// </summary>
public sealed class SystemDnsResolver : IDnsResolver
{
    public Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress, CancellationToken cancellationToken)
        => Dns.GetHostEntryAsync(hostNameOrAddress, cancellationToken);
}
