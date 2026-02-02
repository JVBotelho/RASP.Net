using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rasp.Bootstrapper.Native;

namespace Rasp.Bootstrapper.Configuration;

public class RaspIntegrityService(ILogger<RaspIntegrityService> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        NativeGuard.AssertIntegrity(logger);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}