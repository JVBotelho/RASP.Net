using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Rasp.Instrumentation.AspNetCore.Middleware;

// ReSharper disable once CheckNamespace
namespace Rasp.Instrumentation.AspNetCore.Configuration;

/// <summary>
/// A "Trojan Horse" for Good.
/// Automatically injects the RASP middleware at the very beginning of the pipeline.
/// This guarantees that Security Headers are applied even if the developer forgets 'app.Use...'.
/// </summary>
public sealed class RaspStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.UseMiddleware<RaspSecurityHeadersMiddleware>();

            next(app);
        };
    }
}