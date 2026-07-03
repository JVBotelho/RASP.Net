using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Guard;
using Rasp.Core.Infrastructure;
using Rasp.Core.Telemetry;

namespace Rasp.Core;

public static class RaspCoreExtensions
{
    /// <summary>
    /// Registers the RASP Core services (Telemetry, Contracts, Guards).
    /// This does NOT enable interception; it only lays the groundwork.
    /// </summary>
    public static IServiceCollection AddRaspCore(this IServiceCollection services)
    {
        services.TryAddSingleton<RaspAlertBus>();
        services.TryAddSingleton<IRaspMetrics, RaspMetrics>();

        // Ensure Options is resolvable even if AddRasp(IConfiguration) isn't called.
        services.AddOptions<RaspOptions>();

        // Register the reusable detection engine and its Guard
        services.TryAddSingleton<SqlSinkDetectionEngine>();
        services.TryAddSingleton<SqlSinkGuard>();

        services.TryAddSingleton<SsrfDetectionEngine>();
        services.TryAddSingleton<SsrfGuard>();

        services.TryAddSingleton<DeserializationDetectionEngine>();
        services.TryAddSingleton<DeserializationGuard>();

        services.TryAddSingleton<PathTraversalDetectionEngine>();
        services.TryAddSingleton<PathTraversalGuard>();

        services.TryAddSingleton<CommandInjectionDetectionEngine>();
        services.TryAddSingleton<CommandInjectionGuard>();

        return services;
    }
}