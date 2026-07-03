using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Rasp.Core.Guard;

namespace Rasp.Instrumentation.HttpClient;

public class RaspHttpMessageHandler : DelegatingHandler
{
    private readonly SsrfGuard _guard;

    public RaspHttpMessageHandler(SsrfGuard guard)
    {
        _guard = guard;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Layer 1 Check (Surface Level)
        // Analyzes the initial request URI before letting it go out.
        // NOTE: Auto-redirects are processed deeper in the handler chain (by SocketsHttpHandler).
        // Therefore, this check only sees the initial destination.
        // However, the redirect target's IP will still be caught by Layer 2 (ConnectCallback)
        // because SocketsHttpHandler must resolve DNS and open a new socket for the redirect target.
        _guard.AnalyzeUri(request.RequestUri, "Outbound HTTP");

        // If no exception is thrown by the guard, proceed with the request
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
