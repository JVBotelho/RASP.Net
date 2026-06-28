using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Rasp.Core.Guard;
using Rasp.Core.Exceptions;

namespace Rasp.Instrumentation.HttpClient;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes")]
internal sealed partial class RaspHttpClientBuilderFilter : IHttpMessageHandlerBuilderFilter
{
    private readonly SsrfGuard _guard;
    private readonly IDnsResolver _dnsResolver;
    private readonly ILogger<RaspHttpClientBuilderFilter> _logger;

    public RaspHttpClientBuilderFilter(SsrfGuard guard, IDnsResolver dnsResolver, ILogger<RaspHttpClientBuilderFilter> logger)
    {
        _guard = guard;
        _dnsResolver = dnsResolver;
        _logger = logger;
    }

    [LoggerMessage(EventId = 12, Level = LogLevel.Warning, Message = "SSRF Layer 2 (DNS-rebinding ConnectCallback) not installed for this HttpClient - PrimaryHandler is {HandlerType}, not SocketsHttpHandler. Only Layer 1 (URI-string inspection) is active; hostname-based SSRF that resolves to a blocked IP after Layer 1 checks will not be caught.")]
    private partial void LogLayer2NotInstalled(string handlerType);

    public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next)
    {
        return builder =>
        {
            // Run the inner configurations first
            next(builder);

            // 1. Layer 1 (Surface): Add our SSRF guard handler as the outermost wrapper so it executes first
            builder.AdditionalHandlers.Insert(0, new RaspHttpMessageHandler(_guard));

            // 2. Layer 2 (Deep Inspection): Intercept SocketsHttpHandler.ConnectCallback to prevent DNS Rebinding
            if (builder.PrimaryHandler is SocketsHttpHandler socketsHandler)
            {
                var originalCallback = socketsHandler.ConnectCallback;

                socketsHandler.ConnectCallback = async (context, cancellationToken) =>
                {
                    var host = context.DnsEndPoint.Host;
                    var port = context.DnsEndPoint.Port;

                    // If the host is already an IP literal there is nothing to "resolve" - that literal
                    // IS the connection target. Calling Dns.GetHostEntryAsync on an IP literal instead
                    // does a reverse PTR lookup followed by a forward re-resolution of whatever hostname
                    // comes back, which can return other addresses tied to that hostname - e.g. on a
                    // multi-homed machine (Docker Desktop/WSL2/Hyper-V/VPN) an unrelated virtual
                    // adapter's IPv6 link-local address - that have nothing to do with the connection
                    // actually being made. Skip the round trip entirely and just validate the literal.
                    if (IPAddress.TryParse(host, out var literalIp))
                    {
                        _guard.AnalyzeIp(literalIp, "HttpClient_ConnectCallback");

                        if (originalCallback != null)
                        {
                            return await originalCallback(context, cancellationToken).ConfigureAwait(false);
                        }

                        return await ConnectAsync(literalIp, port, cancellationToken).ConfigureAwait(false);
                    }

                    // We must resolve DNS ourselves to inspect the true IPs the connection will hit
                    // (defends against DNS rebinding between validation and the actual connect).
                    var hostEntry = await _dnsResolver.GetHostEntryAsync(host, cancellationToken).ConfigureAwait(false);

                    // If the application supplied a custom ConnectCallback, defer to it now. We don't
                    // control which resolved address it will actually use, so validate the whole
                    // resolution set upfront as defense-in-depth.
                    //
                    // KNOWN LIMITATION, not fully closed here: `originalCallback` performs its own
                    // connection (its own DNS resolution or its own address selection) after this
                    // validation returns. A malicious/compromised DNS server that answers our lookup
                    // and the callback's differently - the exact rebinding window Layer 2 exists to
                    // close - can still slip a different (unvalidated) IP past this check when a
                    // custom callback is configured. We validate what we resolved, not what the
                    // callback will actually connect to. Closing this fully would mean either
                    // passing the already-validated IPs to the callback by convention (a contract
                    // this project doesn't currently define) or refusing to support custom
                    // ConnectCallback + SSRF protection together; neither is implemented - documented
                    // here as a real gap, not defense-in-depth covering the whole threat.
                    if (originalCallback != null)
                    {
                        foreach (var ip in hostEntry.AddressList)
                        {
                            _guard.AnalyzeIp(ip, "HttpClient_ConnectCallback");
                        }

                        return await originalCallback(context, cancellationToken).ConfigureAwait(false);
                    }

                    if (hostEntry.AddressList.Length == 0)
                    {
                        throw new SocketException((int)SocketError.HostNotFound);
                    }

                    // Try non-link-local addresses first: a link-local address is only reachable on its
                    // own local segment, so it can never legitimately be how we reach a *different* host,
                    // yet resolution on multi-homed machines routinely surfaces one alongside the real
                    // target. Each address is validated immediately before we attempt to connect to it -
                    // never the whole list upfront - so an address we never actually try can never
                    // trigger a block, mirroring the framework's own Happy-Eyeballs address selection.
                    var orderedAddresses = hostEntry.AddressList.OrderBy(ip => IsLinkLocal(ip) ? 1 : 0);

                    Exception? lastException = null;
                    foreach (var ip in orderedAddresses)
                    {
                        _guard.AnalyzeIp(ip, "HttpClient_ConnectCallback");

                        try
                        {
                            return await ConnectAsync(ip, port, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                            lastException = ex;
                        }
                    }

                    throw lastException ?? new SocketException((int)SocketError.HostNotFound);
                };
            }
            else
            {
                LogLayer2NotInstalled(builder.PrimaryHandler?.GetType().Name ?? "null");
            }
        };
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership transfers to the returned NetworkStream (ownsSocket: true) on success, and is disposed explicitly on the failure path.")]
    private static async Task<System.IO.Stream> ConnectAsync(IPAddress ip, int port, CancellationToken cancellationToken)
    {
        var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(ip, port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static bool IsLinkLocal(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal;
        }

        // 169.254.0.0/16
        var bytes = ip.GetAddressBytes();
        return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
    }
}
