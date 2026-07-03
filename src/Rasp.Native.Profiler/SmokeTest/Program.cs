using Rasp.Core.Context;

// Live-attach smoke test for Rasp.Native.Profiler - see ../README.md.
// Marks a string tainted, concatenates it with a clean string via System.String.Concat
// (the sole v1 IL-rewrite target), and checks whether the native profiler's injected
// probe propagated the taint mark to the concatenation result.

Console.WriteLine($"PID: {Environment.ProcessId}");
Console.WriteLine($"CORECLR_ENABLE_PROFILING={Environment.GetEnvironmentVariable("CORECLR_ENABLE_PROFILING")}");
Console.WriteLine($"CORECLR_PROFILER={Environment.GetEnvironmentVariable("CORECLR_PROFILER")}");
Console.WriteLine($"CORECLR_PROFILER_PATH={Environment.GetEnvironmentVariable("CORECLR_PROFILER_PATH")}");
Console.WriteLine($"DOTNET_TieredCompilation={Environment.GetEnvironmentVariable("DOTNET_TieredCompilation")}");

var tainted = "tainted-" + Guid.NewGuid();
RaspTaintSensor.MarkTainted(tainted);

var clean = "-clean-suffix";
// Force this specific overload (string, string) - the only one the profiler targets.
string concatResult = string.Concat(tainted, clean);

Console.WriteLine($"tainted operand IsTainted: {RaspTaintSensor.IsTainted(tainted)}");
Console.WriteLine($"concat result IsTainted:   {RaspTaintSensor.IsTainted(concatResult)}");

if (RaspTaintSensor.IsTainted(concatResult))
{
    Console.WriteLine("PASS: taint propagated through String.Concat");
    return 0;
}

Console.WriteLine("FAIL: taint was not propagated (see README.md smoke test section)");
return 1;
