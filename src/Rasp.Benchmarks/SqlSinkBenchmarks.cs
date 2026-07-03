using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rasp.Core;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Instrumentation.EntityFrameworkCore;
using Rasp.Instrumentation.EntityFrameworkCore.Interceptors;

namespace Rasp.Benchmarks;

public class BookRow
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
}

public class BenchmarkDbContext : DbContext
{
    public DbSet<BookRow> Books { get; set; } = null!;
    public BenchmarkDbContext(DbContextOptions<BenchmarkDbContext> options) : base(options) { }
}

// Runs the same SQL through the real RaspDbCommandInterceptor -> SqlSinkGuard ->
// SqlSinkDetectionEngine pipeline (Hooked) vs. a plain EF Core SQLite context with
// no interceptor at all (NoHook), isolating the sink's real per-call overhead.
[MemoryDiagnoser]
public class SqlSinkBenchmarks
{
    private BenchmarkDbContext _hookedDb = null!;
    private BenchmarkDbContext _plainDb = null!;

    [GlobalSetup]
    public void Setup()
    {
        var options = new RaspOptions { BlockOnDetection = true };

        var hookedServices = new ServiceCollection();
        hookedServices.AddSingleton(Options.Create(options));
        hookedServices.AddSingleton<IRaspMetrics, DummyMetrics>();
        hookedServices.AddLogging();
        hookedServices.AddRaspEntityFrameworkCore();
        hookedServices.AddDbContext<BenchmarkDbContext>((sp, dbOptions) =>
        {
            dbOptions.UseSqlite("DataSource=:memory:");
            dbOptions.UseRaspSqlGuard(sp);
        });
        var hookedProvider = hookedServices.BuildServiceProvider();
        _hookedDb = hookedProvider.GetRequiredService<BenchmarkDbContext>();
        _hookedDb.Database.OpenConnection();
        _hookedDb.Database.EnsureCreated();

        var plainServices = new ServiceCollection();
        plainServices.AddDbContext<BenchmarkDbContext>(dbOptions =>
        {
            dbOptions.UseSqlite("DataSource=:memory:");
        });
        var plainProvider = plainServices.BuildServiceProvider();
        _plainDb = plainProvider.GetRequiredService<BenchmarkDbContext>();
        _plainDb.Database.OpenConnection();
        _plainDb.Database.EnsureCreated();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _hookedDb.Dispose();
        _plainDb.Dispose();
    }

    [Benchmark(Baseline = true)]
    public async Task NoHook_SafeQuery()
        => await _plainDb.Database.ExecuteSqlRawAsync("SELECT * FROM Books WHERE Title = 'Clean Code'").ConfigureAwait(false);

    [Benchmark]
    public async Task Hooked_SafeQuery()
        => await _hookedDb.Database.ExecuteSqlRawAsync("SELECT * FROM Books WHERE Title = 'Clean Code'").ConfigureAwait(false);
}
