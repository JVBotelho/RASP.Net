using System;
using System.Collections.Generic;
using System.IO;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Guard;
using Rasp.Instrumentation.RuntimePatching;
using Rasp.Core;

namespace Rasp.Benchmarks;

public class DummyMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

[MemoryDiagnoser]
public class PathTraversalBenchmarks
{
    private string _fastPathFile = default!;
    private string _slowPathFile = default!;

    [GlobalSetup]
    public void Setup()
    {
        var tempDir = Path.GetTempPath();
        var allowedRoot = Path.Combine(tempDir, "RaspBenchmark_Allowed");
        Directory.CreateDirectory(allowedRoot);

        _fastPathFile = Path.Combine(allowedRoot, "fast.txt");
        // Create the file so FileStream can open it
        File.WriteAllText(_fastPathFile, "test");

        // Slow path: a relative path or something that forces GetFullPath
        _slowPathFile = Path.Combine(allowedRoot, "..", "RaspBenchmark_Allowed", "slow.txt");
        File.WriteAllText(Path.Combine(allowedRoot, "slow.txt"), "test");

        var services = new ServiceCollection();
        var options = new RaspOptions
        {
            AllowedFileRoots = new List<string> { allowedRoot }
        };

        services.AddSingleton(Options.Create(options));
        services.AddSingleton<IRaspMetrics, DummyMetrics>();
        services.AddLogging();
        services.AddRaspCore(); // Includes our new singletons

        var provider = services.BuildServiceProvider();

        // Initialize Runtime Patching (this hooks FileStream and Process.Start)
        RaspRuntimePatching.Initialize(provider);
    }

    [Benchmark(Baseline = true)]
    public void NativeFileStream_NoHook()
    {
        // By bypassing the guard using ReentrancyGuard, we simulate the native unhooked performance
        using var scope = ReentrancyGuard.Enter();
        using var fs = new FileStream(_fastPathFile, FileMode.Open, FileAccess.Read);
    }

    [Benchmark]
    public void FileStream_Hooked_FastPath()
    {
        // This will hit the zero-alloc fast path in PathTraversalDetectionEngine
        using var fs = new FileStream(_fastPathFile, FileMode.Open, FileAccess.Read);
    }

    [Benchmark]
    public void FileStream_Hooked_SlowPath()
    {
        // This will hit the allocating slow path in PathTraversalDetectionEngine
        using var fs = new FileStream(_slowPathFile, FileMode.Open, FileAccess.Read);
    }
}
