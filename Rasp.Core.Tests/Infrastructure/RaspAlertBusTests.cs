using System.Diagnostics.Metrics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics;
using Rasp.Core.Infrastructure;
using Rasp.Core.Telemetry;
using Xunit;

namespace Rasp.Core.Tests.Infrastructure;

public class RaspAlertBusTests
{
    [Fact]
    public void PushAlert_WhenChannelIsFull_ShouldIncrementDroppedCountAndReturnToPool()
    {
        var bus = new RaspAlertBus();
        
        // Channel capacity is 5000. We push 5001 items without reading.
        for (int i = 0; i < 5001; i++)
        {
            bus.PushAlert("XSS", "payload", "context");
        }

        bus.DroppedCount.Should().Be(1);
    }
}

public class RaspMetricsTests
{
    [Fact]
    public void ObservableCounter_ShouldReportDroppedAlerts()
    {
        var services = new ServiceCollection();
        services.AddMetrics();
        var provider = services.BuildServiceProvider();
        var meterFactory = provider.GetRequiredService<IMeterFactory>();

        var bus = new RaspAlertBus();
        // Channel capacity is 5000
        for (int i = 0; i < 5010; i++)
        {
            bus.PushAlert("XSS", "payload", "context");
        }

        var metrics = new RaspMetrics(meterFactory, bus);

        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == RaspMetrics.MeterName)
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };

        long totalDropped = 0;
        meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "rasp.alerts.dropped")
            {
                totalDropped += measurement;
            }
        });
        meterListener.Start();

        meterListener.RecordObservableInstruments();

        totalDropped.Should().Be(10);
    }
}
