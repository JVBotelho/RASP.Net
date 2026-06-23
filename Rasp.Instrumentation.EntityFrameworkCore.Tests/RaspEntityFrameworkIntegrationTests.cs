#pragma warning disable EF1002
using System;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Rasp.Core;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Exceptions;
using Rasp.Core.Infrastructure;
using Rasp.Core.Abstractions;
using Rasp.Instrumentation.EntityFrameworkCore.Interceptors;
using Xunit;

namespace Rasp.Instrumentation.EntityFrameworkCore.Tests;

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
}

public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; }

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}

public class DummyRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

public class RaspEntityFrameworkIntegrationTests
{
    private (AppDbContext Db, IServiceProvider Provider) CreateContext(bool blockOnDetection = true)
    {
        var services = new ServiceCollection();
        
        // Mock metrics/options/bus since we aren't testing DI setup of those fully here
        var options = new RaspOptions { BlockOnDetection = blockOnDetection };
        services.AddSingleton(Options.Create(options));
        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        services.AddSingleton<RaspAlertBus>();
        services.AddSingleton<SqlSinkDetectionEngine>();
        services.AddLogging();
        services.AddSingleton<RaspDbCommandInterceptor>();

        services.AddDbContext<AppDbContext>((sp, dbOptions) =>
        {
            dbOptions.UseSqlite("DataSource=:memory:");
            dbOptions.UseRaspSqlGuard(sp);
        });

        var provider = services.BuildServiceProvider();
        var db = provider.GetRequiredService<AppDbContext>();
        db.Database.OpenConnection();
        db.Database.EnsureCreated();

        return (db, provider);
    }

    [Fact]
    public async Task LegitimateOperations_ShouldNotBeBlocked()
    {
        var (db, _) = CreateContext();

        // 1. Add
        db.Users.Add(new User { Name = "Alice" });
        await db.SaveChangesAsync();

        // 2. Add multiple (Batching uses ;)
        db.Users.Add(new User { Name = "Bob" });
        db.Users.Add(new User { Name = "Charlie" });
        await db.SaveChangesAsync();

        // 3. Union
        var q1 = db.Users.Where(u => u.Name == "Alice");
        var q2 = db.Users.Where(u => u.Name == "Bob");
        var unionQuery = q1.Union(q2).ToList();

        // 4. Remove
        var user = db.Users.First();
        db.Users.Remove(user);
        await db.SaveChangesAsync();

        // 5. TagWith (uses -- comment)
        var tagged = db.Users.TagWith("relatorio_mensal").ToList();

        // If we reach here, no exceptions were thrown.
        db.Users.Count().Should().BeGreaterThanOrEqualTo(0);
    }

    [Fact]
    public async Task RawSqlInjection_Tautology_ShouldThrowRaspSecurityException()
    {
        var (db, _) = CreateContext(blockOnDetection: true);

        // Injecting OR 1=1 without -- to avoid triggering CommentBreakout first
        string maliciousInput = "a' OR 1=1 OR 'a'='";
        
        // We use ExecuteSqlRaw to bypass parameterization and simulate an actual injection reaching the sink
        Func<Task> act = async () => await db.Database.ExecuteSqlRawAsync($"SELECT * FROM Users WHERE Name = '{maliciousInput}'");

        await act.Should().ThrowAsync<RaspSecurityException>()
            .WithMessage("*tautology*");
    }

    [Fact]
    public async Task RawSqlInjection_StackedQuery_ShouldThrowRaspSecurityException()
    {
        var (db, _) = CreateContext(blockOnDetection: true);

        // Stacked query without -- to avoid triggering CommentBreakout first
        string maliciousInput = "a'; DROP TABLE Users; SELECT '";
        
        Func<Task> act = async () => await db.Database.ExecuteSqlRawAsync($"SELECT * FROM Users WHERE Name = '{maliciousInput}'");

        await act.Should().ThrowAsync<RaspSecurityException>()
            .WithMessage("*stacked query*");
    }

    [Fact]
    public async Task AuditMode_ShouldNotThrow_ButShouldLogAlert()
    {
        var (db, provider) = CreateContext(blockOnDetection: false);
        var bus = provider.GetRequiredService<RaspAlertBus>();

        string maliciousInput = "a' OR 1=1 OR 'a'='";
        
        // Will NOT throw because BlockOnDetection = false
        // Will fail because the query is invalid sqlite, but we want to catch the SqliteException to prove Rasp didn't throw
        try
        {
            await db.Database.ExecuteSqlRawAsync($"SELECT * FROM Users WHERE Name = '{maliciousInput}'");
        }
        catch (Microsoft.Data.Sqlite.SqliteException)
        {
            // Expected, query is malformed due to injection breaking sqlite syntax in memory
            // But RASP did NOT throw RaspSecurityException!
        }

        // Verify alert was pushed
        var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(2));
        var alerts = bus.ReadAlertsAsync(cts.Token);
        var enumerator = alerts.GetAsyncEnumerator(cts.Token);
        await enumerator.MoveNextAsync();
        var alert = enumerator.Current;
        
        alert.ThreatType.Should().Be("SQL Injection");
        alert.PayloadSnippet.Should().Be("Tautology");
    }

    [Fact]
    public void DependencyInjection_ShouldResolveInterceptor()
    {
        var services = new ServiceCollection();

        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        services.AddRaspCore();
        services.AddOptions<RaspOptions>();

        services.AddRaspEntityFrameworkCore();
        services.AddLogging(); // required for ILogger<T>

        var provider = services.BuildServiceProvider();

        // Should resolve successfully without throwing
        var interceptor = provider.GetRequiredService<RaspDbCommandInterceptor>();
        interceptor.Should().NotBeNull();
    }
}
