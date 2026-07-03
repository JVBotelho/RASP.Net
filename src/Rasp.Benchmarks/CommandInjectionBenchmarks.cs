using System.Collections.Generic;
using System.Diagnostics;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rasp.Core;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Instrumentation.RuntimePatching;

namespace Rasp.Benchmarks;

[MemoryDiagnoser]
public class CommandInjectionBenchmarks
{
    [GlobalSetup]
    public void Setup()
    {
        var services = new ServiceCollection();
        var options = new RaspOptions
        {
            // Audit-only: isolates pure inspection overhead through the real Process.Start
            // ILHook without needing an allowlist match to avoid a RaspSecurityException.
            BlockOnRuntimePatchingDetection = false,
            AllowedProcesses = new List<string>(),
        };

        services.AddSingleton(Options.Create(options));
        services.AddSingleton<IRaspMetrics, DummyMetrics>();
        services.AddLogging();
        services.AddRaspCore();

        var provider = services.BuildServiceProvider();

        // Hooks Process.Start process-wide, same as production Program.cs wiring.
        RaspRuntimePatching.Initialize(provider);
    }

    private static ProcessStartInfo BuildStartInfo() => new("cmd.exe", "/c exit 0")
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
    };

    [Benchmark(Baseline = true)]
    public void NativeProcessStart_NoHook()
    {
        // Bypasses the ILHook via ReentrancyGuard, simulating unhooked native performance -
        // same technique PathTraversalBenchmarks uses for FileStream.
        using var scope = ReentrancyGuard.Enter();
        using var process = Process.Start(BuildStartInfo());
        process!.WaitForExit();
    }

    [Benchmark]
    public void ProcessStart_Hooked()
    {
        using var process = Process.Start(BuildStartInfo());
        process!.WaitForExit();
    }
}
