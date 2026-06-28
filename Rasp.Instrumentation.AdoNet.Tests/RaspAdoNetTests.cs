using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Rasp.Core;
using Rasp.Core.Configuration;
using Rasp.Core.Exceptions;
using Rasp.Core.Infrastructure;
using Rasp.Core.Abstractions;
using Rasp.Instrumentation.AdoNet.Diagnostics;
using Xunit;

namespace Rasp.Instrumentation.AdoNet.Tests;

public class DummyRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

public class RaspAdoNetTests
{
    private ServiceProvider CreateProvider(bool blockOnDetection = true)
    {
        var services = new ServiceCollection();
        
        var options = new RaspOptions { BlockOnAdoNetDetection = blockOnDetection };
        services.AddSingleton(Options.Create(options));
        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        
        services.AddRaspCore();
        services.AddRaspAdoNet();
        services.AddLogging();

        return services.BuildServiceProvider();
    }

    [Fact]
    public void Synthetic_ShouldExtractCommand_AndBlock_WhenThreatDetected()
    {
        var provider = CreateProvider();
        var observer = provider.GetRequiredService<RaspAdoNetDiagnosticObserver>();
        var bus = provider.GetRequiredService<RaspAlertBus>();

        // Create synthetic listener and subscribe
        using var listener = new DiagnosticListener("SqlClientDiagnosticListener");
        listener.Subscribe(observer);

        // Create a fake command and a fake payload
        var command = new SqlCommand("SELECT * FROM Users WHERE Name = 'a' OR 1=1");
        var payload = new { Command = command };

        // Act - emit the event
        Action act = () => listener.Write("System.Data.SqlClient.WriteCommandBefore", payload);

        // Assert - should throw
        act.Should().Throw<RaspSecurityException>()
           .WithMessage("*tautology*");

        // Validate the alert reached the bus
        var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(2));
        var alerts = bus.ReadAlertsAsync(cts.Token);
        var enumerator = alerts.GetAsyncEnumerator(cts.Token);
        
        enumerator.MoveNextAsync().AsTask().Wait();
        var alert = enumerator.Current;
        
        alert.ThreatType.Should().Be("SQL Injection");
    }

    [Fact]
    public void Synthetic_ShouldNotThrow_WhenAuditMode()
    {
        var provider = CreateProvider(blockOnDetection: false);
        var observer = provider.GetRequiredService<RaspAdoNetDiagnosticObserver>();

        using var listener = new DiagnosticListener("SqlClientDiagnosticListener");
        listener.Subscribe(observer);

        var command = new SqlCommand("SELECT * FROM Users WHERE Name = 'a' OR 1=1");
        var payload = new { Command = command };

        // Act - emit the event
        Action act = () => listener.Write("System.Data.SqlClient.WriteCommandBefore", payload);

        // Assert - should NOT throw
        act.Should().NotThrow<RaspSecurityException>();
    }

    // Note: A full integration test with Microsoft.Data.SqlClient reaching out to a real SQL Server
    // is outside the scope of a fast unit test suite without Testcontainers.
    // But we can verify that the listener is actually picking up Microsoft.Data.SqlClient events
    // if we try to open a dummy connection. It will fail with SqlException, but let's see if 
    // it throws RaspSecurityException first if we issue a command.
    // However, Microsoft.Data.SqlClient won't emit WriteCommandBefore if the connection is not open.
    // So we skip the full integration test here unless we have a real DB. 
    // The synthetic test proves exactly the integration point with DiagnosticListener.
}
