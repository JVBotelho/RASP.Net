using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Rasp.Core;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Infrastructure;
using Rasp.Core.Abstractions;

namespace Rasp.Bootstrapper;

public static partial class RaspDependencyInjection
{
    public static IServiceCollection AddRasp(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        services.AddRaspCore();
        // 1. Configure Options
        services.Configure<RaspOptions>(configuration.GetSection(RaspOptions.SectionName));
        // 2. Register detection engines for generated interceptors
        services.AddSingleton<XssDetectionEngine>();
        services.AddSingleton<SqlInjectionDetectionEngine>();
        services.AddSingleton<IDetectionEngine, CompositeDetectionEngine>();

        // 3. Register Alerting Infrastructure
        services.AddHostedService<RaspAlertConsumerService>();
        return services;
    }
}
