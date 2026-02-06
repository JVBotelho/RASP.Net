using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
// using Rasp.Generated;

namespace Rasp.Bootstrapper;

public static partial class RaspDependencyInjection
{
    public static IServiceCollection AddRasp(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        // 1. Configure Options
        services.Configure<RaspOptions>(configuration.GetSection(RaspOptions.SectionName));
        // services.AddRaspGuards();

        return services;
    }
}