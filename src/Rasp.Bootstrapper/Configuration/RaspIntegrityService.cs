using Microsoft.Extensions.Hosting;
using Rasp.Bootstrapper.Native;

namespace Rasp.Bootstrapper.Configuration;

public class RaspIntegrityService(NativeGuard nativeGuard) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        nativeGuard.AssertIntegrity();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}