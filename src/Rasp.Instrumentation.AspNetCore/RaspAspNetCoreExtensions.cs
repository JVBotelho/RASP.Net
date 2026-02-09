using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rasp.Instrumentation.AspNetCore.Configuration;

namespace Rasp.Instrumentation.AspNetCore;

public static class RaspAspNetCoreServiceExtensions
{
    /// <summary>
    /// Activates RASP for ASP.NET Core (Zero-Touch Configuration).
    /// <para>
    /// Registers the <see cref="IStartupFilter"/> that automatically injects the security middleware.
    /// Just call this in your DI container, and the RASP is live.
    /// </para>
    /// </summary>
    public static IServiceCollection AddRaspAspNetCore(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Transient<IStartupFilter, RaspStartupFilter>());

        return services;
    }
}