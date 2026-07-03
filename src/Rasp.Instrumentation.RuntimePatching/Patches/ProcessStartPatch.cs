using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Mono.Cecil.Cil;
using MonoMod.Cil;
using MonoMod.RuntimeDetour;
using Rasp.Core.Guard;

namespace Rasp.Instrumentation.RuntimePatching.Patches;

public static class ProcessStartPatch
{
    private static CommandInjectionGuard? _guard;
    private static readonly List<ILHook> _hooks = new();

    public static void Apply(IServiceProvider serviceProvider)
    {
        _guard = serviceProvider.GetService<CommandInjectionGuard>();

        // In .NET Core, Process.Start() instance method is the ultimate choke point.
        var startMethod = typeof(Process).GetMethod("Start", Type.EmptyTypes);

        if (startMethod != null)
        {
            var hook = new ILHook(startMethod, InjectProcessInspection);
            _hooks.Add(hook);
        }
    }

    private static void InjectProcessInspection(ILContext il)
    {
        var cursor = new ILCursor(il);

        // Arg 0 is 'this' (Process instance). We load it to extract StartInfo.
        cursor.Emit(OpCodes.Ldarg_0);
        cursor.EmitDelegate<Action<Process>>(InspectProcess);
    }

    private static void InspectProcess(Process process)
    {
        if (_guard == null || ReentrancyGuard.IsInGuard) return;

        using var scope = ReentrancyGuard.Enter();

        var startInfo = process.StartInfo;
        if (startInfo != null)
        {
            var exe = startInfo.FileName;
            var useShellExecute = startInfo.UseShellExecute;

            // Reconstruct arguments list. If ArgumentList is empty, fallback to parsing Arguments as a single string token.
            IReadOnlyList<string> args;
            if (startInfo.ArgumentList.Count > 0)
            {
                args = startInfo.ArgumentList;
            }
            else if (!string.IsNullOrWhiteSpace(startInfo.Arguments))
            {
                args = new[] { startInfo.Arguments };
            }
            else
            {
                args = Array.Empty<string>();
            }

            _guard.AnalyzeProcessExecution(exe, args, useShellExecute, "Process.Start");
        }
    }
}
