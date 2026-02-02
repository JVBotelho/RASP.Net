using Grpc.AspNetCore.Server;
using Microsoft.Extensions.DependencyInjection;
using Rasp.Bootstrapper.Configuration;
using Rasp.Core;
using Rasp.Instrumentation.Grpc.Interceptors;

namespace Rasp.Bootstrapper;

/// <summary>
/// Provides extension methods to easily register RASP services.
/// </summary>
public static class RaspDependencyInjection
{
    /// <summary>
    /// Adds the RASP (Runtime Application Self-Protection) services to the DI container.
    /// This method registers detection engines, telemetry, and gRPC interceptors.
    /// </summary>
    /// <param name="services">The application service collection.</param>
    /// <param name="configureOptions">Optional delegate to configure RASP behavior.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddRasp(
        this IServiceCollection services,
        Action<RaspOptions>? configureOptions = null)
    {
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        services.AddRaspCore();

        services.AddSingleton<SecurityInterceptor>();

        services.PostConfigure<GrpcServiceOptions>(options =>
        {
            options.Interceptors.Add<SecurityInterceptor>();
        });
        
        services.AddHostedService<RaspIntegrityService>();

        return services;
    }
}