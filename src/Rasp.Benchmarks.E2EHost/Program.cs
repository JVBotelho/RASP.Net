using System.Diagnostics;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Rasp.Bootstrapper;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Instrumentation.EntityFrameworkCore;
using Rasp.Instrumentation.HttpClient;
using Rasp.Instrumentation.RuntimePatching;
using Testcontainers.PostgreSql;

var raspEnabled = string.Equals(Environment.GetEnvironmentVariable("RASP_MODE"), "on", StringComparison.OrdinalIgnoreCase);
var port = int.Parse(Environment.GetEnvironmentVariable("PORT") ?? "5100");
var echoPort = int.Parse(Environment.GetEnvironmentVariable("ECHO_PORT") ?? "5199");
var ssrfDnsCacheSeconds = double.Parse(Environment.GetEnvironmentVariable("SSRF_DNS_CACHE_SECONDS") ?? "0", System.Globalization.CultureInfo.InvariantCulture);
var ssrfDnsLatencyMs = double.Parse(Environment.GetEnvironmentVariable("SSRF_DNS_LATENCY_MS") ?? "0", System.Globalization.CultureInfo.InvariantCulture);

// The "external" system the /fetch endpoint calls out to (the SSRF sink's real target).
// Deliberately reached by HOSTNAME, not IP literal: RaspHttpClientBuilderFilter's ConnectCallback
// skips DNS resolution entirely for an IP-literal host (nothing to resolve), so an IP-literal
// target would never exercise Layer 2's Dns.GetHostEntryAsync call - or, therefore, the SSRF DNS
// cache this host exists to benchmark. The machine's own hostname resolves to its real adapter
// addresses (RFC 1918 private, not blocked by default) and forces the real resolution path.
var fetchHost = Dns.GetHostName();
StartEchoServer(echoPort);

var allowedRoot = Path.Combine(Path.GetTempPath(), "RaspE2EHost_Allowed");
Directory.CreateDirectory(allowedRoot);
var sampleFile = Path.Combine(allowedRoot, "sample.txt");
await File.WriteAllTextAsync(sampleFile, new string('a', 4096)).ConfigureAwait(false);

// Real Postgres (not on-disk SQLite) so concurrent writers don't serialize on a single-
// writer file lock - that would measure SQLite's own contention, not the RASP SQL guard.
var postgres = new PostgreSqlBuilder().WithImage("postgres:16.11-alpine").Build();
await postgres.StartAsync().ConfigureAwait(false);
var connectionString = postgres.GetConnectionString();

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();

if (raspEnabled)
{
    var raspConfig = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Rasp:BlockOnDetection"] = "true",
            ["Rasp:BlockOnRuntimePatchingDetection"] = "true",
            ["Rasp:BlockOnSsrfDetection"] = "true",
        })
        .Build();

    builder.Services.AddRasp(raspConfig);
    builder.Services.Configure<RaspOptions>(opt =>
    {
        opt.AllowedFileRoots = new List<string> { allowedRoot };
        opt.AllowedProcesses = new List<string> { "cmd.exe" };
        opt.SsrfDnsCacheDuration = TimeSpan.FromSeconds(ssrfDnsCacheSeconds);
    });
    builder.Services.AddRaspEntityFrameworkCore();
    builder.Services.AddRaspHttpClient();

    if (ssrfDnsLatencyMs > 0)
    {
        // Same-machine hostname resolution is answered from local interface state, not a real
        // network round trip - it can't demonstrate SsrfDnsCacheDuration's value. Overrides the
        // resolver AddRaspHttpClient() just wired with one that adds a fixed delay before the
        // real (still-real) resolution, simulating a genuine recursive-resolver-cache-hit RTT:
        // 20ms sits mid-range of published DNS latency data (cache hit at the resolver: single-
        // digit-to-tens of ms; full uncached hierarchy walk: 50-200ms) - see the citation in
        // docs/ADR/006-sink-instrumentation-strategy.md's DNS cache benchmark section.
        builder.Services.AddSingleton<IDnsResolver>(sp => new CachingDnsResolver(
            new DelayedDnsResolver(new SystemDnsResolver(), TimeSpan.FromMilliseconds(ssrfDnsLatencyMs)),
            sp.GetRequiredService<IOptions<RaspOptions>>()));
    }
}
else
{
    builder.Services.AddSingleton<IRaspMetrics, NoOpRaspMetrics>();
}

builder.Services.AddHttpClient("External");

builder.Services.AddDbContext<E2EDbContext>((sp, opts) =>
{
    opts.UseNpgsql(connectionString);
    if (raspEnabled)
    {
        opts.UseRaspSqlGuard(sp);
    }
});

builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<E2EDbContext>();
    await db.Database.EnsureCreatedAsync().ConfigureAwait(false);
}

if (raspEnabled)
{
    RaspRuntimePatching.Initialize(app.Services);
}

app.Lifetime.ApplicationStopping.Register(() => postgres.DisposeAsync().AsTask().GetAwaiter().GetResult());

app.MapGet("/files/read", () =>
{
    using var fs = new FileStream(sampleFile, FileMode.Open, FileAccess.Read);
    using var reader = new StreamReader(fs);
    var content = reader.ReadToEnd();
    return Results.Ok(content.Length);
});

app.MapPost("/proc/run", () =>
{
    var psi = new ProcessStartInfo("cmd.exe", "/c exit 0")
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
    };
    using var process = Process.Start(psi);
    process!.WaitForExit();
    return Results.Ok(process.ExitCode);
});

app.MapGet("/fetch", async (IHttpClientFactory factory) =>
{
    var client = factory.CreateClient("External");
    var response = await client.GetAsync(new Uri($"http://{fetchHost}:{echoPort}/")).ConfigureAwait(false);
    return Results.Ok((int)response.StatusCode);
});

app.MapPost("/books", async (E2EDbContext db) =>
{
    db.Books.Add(new BookRow { Title = "Clean Code" });
    await db.SaveChangesAsync().ConfigureAwait(false);
    var count = await db.Books.CountAsync().ConfigureAwait(false);
    return Results.Ok(count);
});

await app.RunAsync().ConfigureAwait(false);

static void StartEchoServer(int listenPort)
{
    var echoBuilder = WebApplication.CreateBuilder();
    echoBuilder.Logging.ClearProviders();
    echoBuilder.WebHost.UseUrls($"http://0.0.0.0:{listenPort}");
    var echoApp = echoBuilder.Build();
    echoApp.MapGet("/", () => Results.Ok());
    _ = echoApp.RunAsync();
}

public class BookRow
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
}

public class E2EDbContext : DbContext
{
    public DbSet<BookRow> Books { get; set; } = null!;
    public E2EDbContext(DbContextOptions<E2EDbContext> options) : base(options) { }
}

public class NoOpRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

// Benchmark-only: simulates realistic DNS round-trip latency on top of a real (but locally
// near-instant, same-machine) resolution, so the SSRF DNS cache's effect is measurable against
// a representative cost instead of the ~free cost of resolving this machine's own hostname.
public sealed class DelayedDnsResolver : IDnsResolver
{
    private readonly IDnsResolver _inner;
    private readonly TimeSpan _delay;

    public DelayedDnsResolver(IDnsResolver inner, TimeSpan delay)
    {
        _inner = inner;
        _delay = delay;
    }

    public async Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress, CancellationToken cancellationToken)
    {
        await Task.Delay(_delay, cancellationToken).ConfigureAwait(false);
        return await _inner.GetHostEntryAsync(hostNameOrAddress, cancellationToken).ConfigureAwait(false);
    }
}
