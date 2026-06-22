using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rasp.Core.Infrastructure;

#pragma warning disable CA1848
#pragma warning disable CA2007

namespace Rasp.Bootstrapper;

public sealed class RaspAlertConsumerService : BackgroundService
{
    private readonly RaspAlertBus _alertBus;
    private readonly ILogger<RaspAlertConsumerService> _logger;

    public RaspAlertConsumerService(RaspAlertBus alertBus, ILogger<RaspAlertConsumerService> logger)
    {
        _alertBus = alertBus;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("RaspAlertConsumerService started. Listening for RASP alerts.");

        await foreach (var alert in _alertBus.ReadAlertsAsync(stoppingToken).ConfigureAwait(false))
        {
            // Log the alert as a structured log event (which can be scraped by DataDog/Splunk etc)
            _logger.LogWarning(
                "RASP THREAT DETECTED | Type: {ThreatType} | Payload: {PayloadSnippet} | Context: {Context}",
                alert.ThreatType,
                alert.PayloadSnippet,
                alert.Context);
        }
    }
}
