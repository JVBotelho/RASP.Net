using System.Diagnostics;
using System.Linq;
using System.Net.Http;

var raspOnUrl = GetArg(args, "--rasp-on") ?? "http://127.0.0.1:5100";
var raspOffUrl = GetArg(args, "--rasp-off") ?? "http://127.0.0.1:5101";
var raspOnCachedUrl = GetArg(args, "--rasp-on-cached");
var durationSeconds = int.Parse(GetArg(args, "--duration") ?? "15");
var concurrency = int.Parse(GetArg(args, "--concurrency") ?? "25");
var warmupSeconds = int.Parse(GetArg(args, "--warmup") ?? "3");

var endpoints = new (string Name, HttpMethod Method, string Path)[]
{
    ("Path Traversal (/files/read)", HttpMethod.Get, "/files/read"),
    ("Command Injection (/proc/run)", HttpMethod.Post, "/proc/run"),
    ("SSRF (/fetch)", HttpMethod.Get, "/fetch"),
    ("SQL (/books)", HttpMethod.Post, "/books"),
};

Console.WriteLine($"Concurrency={concurrency}, Duration={durationSeconds}s, Warmup={warmupSeconds}s per (endpoint x mode)\n");

var results = new List<(string Endpoint, string Mode, Stats Stats)>();

foreach (var endpoint in endpoints)
{
    foreach (var (mode, baseUrl) in new[] { ("RASP off", raspOffUrl), ("RASP on", raspOnUrl) })
    {
        Console.WriteLine($"Running {endpoint.Name} against {mode} ({baseUrl})...");
        var stats = await RunLoadAsync(baseUrl, endpoint.Method, endpoint.Path, concurrency, warmupSeconds, durationSeconds).ConfigureAwait(false);
        results.Add((endpoint.Name, mode, stats));
        Console.WriteLine($"  requests={stats.Count} p50={stats.P50:F0}us p95={stats.P95:F0}us p99={stats.P99:F0}us mean={stats.Mean:F0}us errors={stats.Errors}");
    }
}

// Extra pass: only meaningful for the SSRF endpoint (the one guard with an opt-in DNS cache),
// run against a third instance configured with SsrfDnsCacheDuration > 0.
if (raspOnCachedUrl != null)
{
    var ssrf = endpoints.First(e => e.Name.Contains("SSRF", StringComparison.Ordinal));
    Console.WriteLine($"Running {ssrf.Name} against RASP on (DNS cached) ({raspOnCachedUrl})...");
    var cachedStats = await RunLoadAsync(raspOnCachedUrl, ssrf.Method, ssrf.Path, concurrency, warmupSeconds, durationSeconds).ConfigureAwait(false);
    results.Add((ssrf.Name, "RASP on (DNS cached)", cachedStats));
    Console.WriteLine($"  requests={cachedStats.Count} p50={cachedStats.P50:F0}us p95={cachedStats.P95:F0}us p99={cachedStats.P99:F0}us mean={cachedStats.Mean:F0}us errors={cachedStats.Errors}");
}

Console.WriteLine("\n| Endpoint | Mode | Requests | p50 (us) | p95 (us) | p99 (us) | Mean (us) | Errors |");
Console.WriteLine("|---|---|---:|---:|---:|---:|---:|---:|");
foreach (var (endpointName, mode, stats) in results)
{
    Console.WriteLine($"| {endpointName} | {mode} | {stats.Count} | {stats.P50:F0} | {stats.P95:F0} | {stats.P99:F0} | {stats.Mean:F0} | {stats.Errors} |");
}

static string? GetArg(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
        {
            return args[i + 1];
        }
    }

    return null;
}

static async Task<Stats> RunLoadAsync(string baseUrl, HttpMethod method, string path, int concurrency, int warmupSeconds, int durationSeconds)
{
    using var handler = new SocketsHttpHandler
    {
        MaxConnectionsPerServer = concurrency * 2,
        PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
    };
    using var client = new HttpClient(handler) { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(30) };

    var uri = new Uri(path, UriKind.Relative);

    async Task<bool> SendOnceAsync()
    {
        using var request = new HttpRequestMessage(method, uri);
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        return response.IsSuccessStatusCode;
    }

    // Warmup: establish connections, let JIT tier up, before the timed window starts.
    var warmupEnd = Stopwatch.GetTimestamp() + (long)(warmupSeconds * Stopwatch.Frequency);
    var warmupTasks = new Task[concurrency];
    for (int i = 0; i < concurrency; i++)
    {
        warmupTasks[i] = Task.Run(async () =>
        {
            while (Stopwatch.GetTimestamp() < warmupEnd)
            {
                try { await SendOnceAsync().ConfigureAwait(false); } catch { /* ignore during warmup */ }
            }
        });
    }
    await Task.WhenAll(warmupTasks).ConfigureAwait(false);

    var latenciesUs = new System.Collections.Concurrent.ConcurrentBag<double>();
    var errors = 0;
    var runEnd = Stopwatch.GetTimestamp() + (long)(durationSeconds * Stopwatch.Frequency);

    var workers = new Task[concurrency];
    for (int i = 0; i < concurrency; i++)
    {
        workers[i] = Task.Run(async () =>
        {
            while (Stopwatch.GetTimestamp() < runEnd)
            {
                var start = Stopwatch.GetTimestamp();
                try
                {
                    var ok = await SendOnceAsync().ConfigureAwait(false);
                    var elapsedUs = Stopwatch.GetElapsedTime(start).TotalMicroseconds;
                    latenciesUs.Add(elapsedUs);
                    if (!ok) Interlocked.Increment(ref errors);
                }
                catch
                {
                    Interlocked.Increment(ref errors);
                }
            }
        });
    }
    await Task.WhenAll(workers).ConfigureAwait(false);

    var sorted = latenciesUs.ToArray();
    Array.Sort(sorted);
    return new Stats
    {
        Count = sorted.Length,
        Errors = errors,
        Mean = sorted.Length == 0 ? 0 : sorted.Average(),
        P50 = Percentile(sorted, 0.50),
        P95 = Percentile(sorted, 0.95),
        P99 = Percentile(sorted, 0.99),
    };
}

static double Percentile(double[] sorted, double p)
{
    if (sorted.Length == 0) return 0;
    var index = (int)Math.Ceiling(p * sorted.Length) - 1;
    index = Math.Clamp(index, 0, sorted.Length - 1);
    return sorted[index];
}

internal struct Stats
{
    public int Count;
    public int Errors;
    public double Mean;
    public double P50;
    public double P95;
    public double P99;
}
