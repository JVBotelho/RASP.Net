using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rasp.Core.Abstractions;
using Rasp.Core.Engine;
using Rasp.Core.Telemetry;

namespace Rasp.Core;

public static class DependencyInjection
{
    /// <summary>
    /// Registers the RASP Core services (Telemetry, Contracts).
    /// This does NOT enable interception; it only lays the groundwork.
    /// </summary>
    public static IServiceCollection AddRaspCore(this IServiceCollection services)
    {
        services.TryAddSingleton<IRaspMetrics, RaspMetrics>();
        services.TryAddSingleton<IDetectionEngine, SqlInjectionDetectionEngine>();

        return services;
    }
}