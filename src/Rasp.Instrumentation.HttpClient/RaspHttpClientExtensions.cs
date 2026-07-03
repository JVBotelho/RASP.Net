using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Rasp.Core;

namespace Rasp.Instrumentation.HttpClient;

public static class RaspHttpClientExtensions
{
    /// <summary>
    /// Registers the RASP HttpClient SSRF sensor.
    /// This intercepts all outgoing HTTP requests created via IHttpClientFactory 
    /// to block Server-Side Request Forgery attacks.
    /// </summary>
    public static IServiceCollection AddRaspHttpClient(this IServiceCollection services)
    {
        services.AddRaspCore(); // Ensure core engines and guards are registered

        services.TryAddSingleton<SystemDnsResolver>();
        services.TryAddSingleton<IDnsResolver>(sp => new CachingDnsResolver(
            sp.GetRequiredService<SystemDnsResolver>(),
            sp.GetRequiredService<IOptions<Rasp.Core.Configuration.RaspOptions>>()));

        // Register the filter that will inject our handler into all HttpClients
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHttpMessageHandlerBuilderFilter, RaspHttpClientBuilderFilter>());

        return services;
    }
}
