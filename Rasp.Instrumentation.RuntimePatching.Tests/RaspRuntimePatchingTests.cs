using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Rasp.Core.Exceptions;
using Rasp.Core.Guard;
using Rasp.Core.Infrastructure;
using Rasp.Instrumentation.RuntimePatching;
using Xunit;

namespace Rasp.Instrumentation.RuntimePatching.Tests;

public class DummyRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

public class RaspRuntimePatchingTests : IDisposable
{
    private readonly IServiceProvider _serviceProvider;
    private readonly string _allowedRoot;

    public RaspRuntimePatchingTests()
    {
        _allowedRoot = Path.Combine(Path.GetTempPath(), "RaspTests_Allowed");
        Directory.CreateDirectory(_allowedRoot);

        var services = new ServiceCollection();
        var options = new RaspOptions
        {
            AllowedFileRoots = new List<string> { _allowedRoot },
            AllowedProcesses = new List<string> { "echo" }
        };

        services.AddSingleton(Options.Create(options));
        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        services.AddLogging();

        // Add Core dependencies
        services.AddSingleton<RaspAlertBus>();
        services.AddSingleton<PathTraversalDetectionEngine>();
        services.AddSingleton<CommandInjectionDetectionEngine>();
        services.AddSingleton<PathTraversalGuard>();
        services.AddSingleton<CommandInjectionGuard>();

        _serviceProvider = services.BuildServiceProvider();

        // Initialize Runtime Patching
        RaspRuntimePatching.Initialize(_serviceProvider);
    }

    public void Dispose()
    {
        if (Directory.Exists(_allowedRoot))
        {
            Directory.Delete(_allowedRoot, true);
        }
    }

    [Fact]
    public void FileStream_WithinAllowedRoot_ShouldSucceed()
    {
        var testFile = Path.Combine(_allowedRoot, "test1.txt");

        Action act = () =>
        {
            using var fs = new FileStream(testFile, FileMode.Create, FileAccess.Write);
            fs.WriteByte(1);
        };

        act.Should().NotThrow();
    }

    [Fact]
    public void FileStream_OutsideAllowedRoot_ShouldThrowRaspSecurityException()
    {
        var unauthorizedDir = Path.Combine(Path.GetTempPath(), "RaspTests_Unauthorized");
        Directory.CreateDirectory(unauthorizedDir);
        var testFile = Path.Combine(unauthorizedDir, "test2.txt");

        try
        {
            Action act = () =>
            {
                using var fs = new FileStream(testFile, FileMode.Create, FileAccess.Write);
            };

            act.Should().Throw<RaspSecurityException>()
               .WithMessage("*Path resolves outside allowed roots*");
        }
        finally
        {
            Directory.Delete(unauthorizedDir, true);
        }
    }

    [Fact]
    public void FileStream_Reentrancy_ShouldNotStackOverflow()
    {
        // To test reentrancy, we manually enter the guard, then try to open a file outside the root.
        // It should NOT throw RaspSecurityException because the guard will bypass the hook.

        var unauthorizedDir = Path.Combine(Path.GetTempPath(), "RaspTests_Unauthorized_Reentrancy");
        Directory.CreateDirectory(unauthorizedDir);
        var testFile = Path.Combine(unauthorizedDir, "test3.txt");

        try
        {
            Action act = () =>
            {
                using var scope = ReentrancyGuard.Enter();
                // This would normally throw, but since we are "in guard", it bypasses the hook!
                using var fs = new FileStream(testFile, FileMode.Create, FileAccess.Write);
            };

            act.Should().NotThrow("Because the hook is bypassed when ReentrancyGuard is active.");
        }
        finally
        {
            Directory.Delete(unauthorizedDir, true);
        }
    }

    [Fact]
    public void ProcessStart_AllowedExecutable_ShouldSucceed()
    {
        // In theory, echo should just run and exit.
        // However, on Windows, 'echo' is a shell built-in, so Process.Start might fail with "The system cannot find the file specified"
        // But the RASP shouldn't throw a RaspSecurityException.

        Action act = () =>
        {
            try
            {
                var psi = new ProcessStartInfo("echo", "hello");
                Process.Start(psi);
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Ignore standard OS exceptions, as long as it's not a RASP exception
            }
        };

        act.Should().NotThrow<RaspSecurityException>();
    }

    [Fact]
    public void ProcessStart_NotAllowedExecutable_ShouldThrowRaspSecurityException()
    {
        Action act = () =>
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c echo test");
            Process.Start(psi);
        };

        act.Should().Throw<RaspSecurityException>()
           .WithMessage("*not in allowlist*");
    }
}
