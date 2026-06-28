using System;
using System.Threading.Tasks;
using Rasp.Core.Context;
using Rasp.Core.Infrastructure;
using Xunit;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;

namespace Rasp.Core.Tests.Context;

public class RaspContextTests
{
    [Fact]
    public void BeginScope_ShouldRestorePreviousContextOnDispose()
    {
        var context1 = new RaspContext { CorrelationId = "1", Source = "S1" };
        var context2 = new RaspContext { CorrelationId = "2", Source = "S2" };

        RaspExecutionContext.Current.Should().BeNull();

        using (RaspExecutionContext.BeginScope(context1))
        {
            RaspExecutionContext.Current.Should().Be(context1);

            using (RaspExecutionContext.BeginScope(context2))
            {
                RaspExecutionContext.Current.Should().Be(context2);
            }

            RaspExecutionContext.Current.Should().Be(context1);
        }

        RaspExecutionContext.Current.Should().BeNull();
    }

    [Fact]
    public async Task PushAlert_WithRaspContext_ShouldPropagateStructuredFields()
    {
        var bus = new RaspAlertBus();

        var ctx = new RaspContext
        {
            CorrelationId = "TestCorrId",
            Source = "TestSource",
            RemoteId = "127.0.0.1",
            TraceId = "TestTrace",
            StartedUtc = DateTime.UtcNow
        };

        bus.PushAlert(ctx, "TestThreat", "TestPayload", "TestSink");

        RaspAlertEvent? alertEvent = null;
        await foreach (var alert in bus.ReadAlertsAsync(default))
        {
            alertEvent = alert;
            break;
        }

        alertEvent.Should().NotBeNull();
        var e = alertEvent.Value;
        e.ThreatType.Should().Be("TestThreat");
        e.PayloadSnippet.Should().Be("TestPayload");
        e.Context.Should().Be("TestSink");
        e.CorrelationId.Should().Be("TestCorrId");
        e.Source.Should().Be("TestSource");
        e.RemoteId.Should().Be("127.0.0.1");
        e.TraceId.Should().Be("TestTrace");
    }
}
