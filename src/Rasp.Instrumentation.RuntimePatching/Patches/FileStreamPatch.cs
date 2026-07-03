using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Mono.Cecil.Cil;
using MonoMod.Cil;
using MonoMod.RuntimeDetour;
using Rasp.Core.Guard;

namespace Rasp.Instrumentation.RuntimePatching.Patches;

public static class FileStreamPatch
{
    private static PathTraversalGuard? _guard;
    private static readonly List<ILHook> _hooks = new();

    public static void Apply(IServiceProvider serviceProvider)
    {
        _guard = serviceProvider.GetService<PathTraversalGuard>();

        var fileStreamType = typeof(FileStream);

        // Hook all public constructors of FileStream that take a string as the first parameter
        var ctors = fileStreamType.GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        foreach (var ctor in ctors)
        {
            var parameters = ctor.GetParameters();
            if (parameters.Length > 0 && parameters[0].ParameterType == typeof(string))
            {
                var hook = new ILHook(ctor, InjectPathInspection);
                _hooks.Add(hook);
            }
        }

        // Hook File.OpenHandle (introduced in .NET 6)
        var openHandleMethod = typeof(File).GetMethod("OpenHandle", BindingFlags.Public | BindingFlags.Static);
        if (openHandleMethod != null)
        {
            var hook = new ILHook(openHandleMethod, InjectPathInspectionStatic);
            _hooks.Add(hook);
        }
    }

    private static void InjectPathInspection(ILContext il)
    {
        var cursor = new ILCursor(il);

        // Arg 0 is 'this' (FileStream instance). Arg 1 is the 'path' string.
        cursor.Emit(OpCodes.Ldarg_1);
        cursor.EmitDelegate<Action<string>>(InspectPath);
    }

    private static void InjectPathInspectionStatic(ILContext il)
    {
        var cursor = new ILCursor(il);

        // Arg 0 is the 'path' string since it's a static method.
        cursor.Emit(OpCodes.Ldarg_0);
        cursor.EmitDelegate<Action<string>>(InspectPath);
    }

    private static void InspectPath(string path)
    {
        if (_guard == null || ReentrancyGuard.IsInGuard) return;

        using var scope = ReentrancyGuard.Enter();
        _guard.AnalyzePath(path, "FileStream/OpenHandle");
    }
}
