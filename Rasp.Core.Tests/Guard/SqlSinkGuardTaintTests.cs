using System;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Context;
using Rasp.Core.Engine;
using Rasp.Core.Exceptions;
using Rasp.Core.Guard;
using Rasp.Core.Infrastructure;
using Xunit;

namespace Rasp.Core.Tests.Guard;

public class NoOpRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

public class SqlSinkGuardTaintTests
{
    private static SqlSinkGuard CreateGuard(RaspAlertBus bus, bool blockOnDetection)
    {
        var options = Options.Create(new RaspOptions { BlockOnDetection = blockOnDetection });
        return new SqlSinkGuard(
            new SqlSinkDetectionEngine(),
            bus,
            new NoOpRaspMetrics(),
            options,
            NullLogger<SqlSinkGuard>.Instance);
    }

    private static string ReadNextAlertPayload(RaspAlertBus bus)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var enumerator = bus.ReadAlertsAsync(cts.Token).GetAsyncEnumerator(cts.Token);
        enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult();
        return enumerator.Current.PayloadSnippet + " " + enumerator.Current.Context;
    }

    [Fact]
    public void AnalyzeCommand_TaintedInput_AlertReflectsTainted()
    {
        var bus = new RaspAlertBus();
        var guard = CreateGuard(bus, blockOnDetection: false);

        var commandText = "SELECT * FROM Users WHERE Name = '" + Guid.NewGuid() + "' OR 1=1 --";
        RaspTaintSensor.MarkTainted(commandText);

        guard.AnalyzeCommand(commandText, "Test Sink");

        var alertText = ReadNextAlertPayload(bus);
        Assert.Contains("[Tainted]", alertText);
    }

    [Fact]
    public void AnalyzeCommand_UntaintedInput_AlertDoesNotClaimTainted()
    {
        var bus = new RaspAlertBus();
        var guard = CreateGuard(bus, blockOnDetection: false);

        // Not marked tainted - a coincidental pattern match on operator-authored SQL, e.g.
        var commandText = "SELECT * FROM Users WHERE Name = '" + Guid.NewGuid() + "' OR 1=1 --";

        guard.AnalyzeCommand(commandText, "Test Sink");

        var alertText = ReadNextAlertPayload(bus);
        Assert.DoesNotContain("[Tainted]", alertText);
    }

    [Fact]
    public void AnalyzeCommand_TaintedInput_StillBlocksWhenConfiguredTo()
    {
        // Taint is enrichment only - it must never become a requirement for blocking to
        // fire, since v1 propagation coverage is narrow (see SqlSinkGuard.cs).
        var bus = new RaspAlertBus();
        var guard = CreateGuard(bus, blockOnDetection: true);

        var commandText = "SELECT * FROM Users WHERE Name = '" + Guid.NewGuid() + "' OR 1=1 --";
        // Deliberately NOT marking this tainted.

        Assert.Throws<RaspSecurityException>(() => guard.AnalyzeCommand(commandText, "Test Sink"));
    }
}
