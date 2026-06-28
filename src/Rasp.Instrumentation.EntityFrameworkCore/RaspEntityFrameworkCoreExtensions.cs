using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rasp.Core;
using Rasp.Core.Engine;
using Rasp.Instrumentation.EntityFrameworkCore.Interceptors;

namespace Rasp.Instrumentation.EntityFrameworkCore;

public static class RaspEntityFrameworkCoreExtensions
{
    /// <summary>
    /// Registers the EF Core SQL Sink Sensor in the dependency injection container.
    /// This should be called along with AddRaspCore().
    /// </summary>
    public static IServiceCollection AddRaspEntityFrameworkCore(this IServiceCollection services)
    {
        // Ensure core dependencies (Metrics, AlertBus) are registered.
        services.AddRaspCore();
        
        // Ensure Options is available even if unconfigured, to prevent DI failure
        services.AddOptions<Rasp.Core.Configuration.RaspOptions>();

        services.TryAddSingleton<SqlSinkDetectionEngine>();
        services.TryAddSingleton<RaspDbCommandInterceptor>();
        return services;
    }

    /// <summary>
    /// Adds the RASP SQL Guard interceptor to the DbContext options.
    /// </summary>
    public static DbContextOptionsBuilder UseRaspSqlGuard(this DbContextOptionsBuilder builder, IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        var interceptor = serviceProvider.GetRequiredService<RaspDbCommandInterceptor>();
        return builder.AddInterceptors(interceptor);
    }
}
