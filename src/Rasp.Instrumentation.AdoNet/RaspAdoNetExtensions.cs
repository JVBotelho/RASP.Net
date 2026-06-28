using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Rasp.Core;
using Rasp.Instrumentation.AdoNet.Diagnostics;

namespace Rasp.Instrumentation.AdoNet;

public static class RaspAdoNetExtensions
{
    /// <summary>
    /// Registers the ADO.NET SQL Sink Sensor in the dependency injection container.
    /// This should be called along with AddRaspCore().
    /// </summary>
    public static IServiceCollection AddRaspAdoNet(this IServiceCollection services)
    {
        services.AddRaspCore();
        services.TryAddSingleton<RaspAdoNetDiagnosticObserver>();
        services.AddHostedService<RaspAdoNetHostedService>();
        return services;
    }
}

[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes")]
internal sealed class RaspAdoNetHostedService : IHostedService
{
    private readonly RaspAdoNetDiagnosticObserver _observer;
    private IDisposable? _subscription;

    public RaspAdoNetHostedService(RaspAdoNetDiagnosticObserver observer)
    {
        _observer = observer;
    }

    public System.Threading.Tasks.Task StartAsync(System.Threading.CancellationToken cancellationToken)
    {
        _subscription = DiagnosticListener.AllListeners.Subscribe(_observer);
        return System.Threading.Tasks.Task.CompletedTask;
    }

    public System.Threading.Tasks.Task StopAsync(System.Threading.CancellationToken cancellationToken)
    {
        _subscription?.Dispose();
        return System.Threading.Tasks.Task.CompletedTask;
    }
}
