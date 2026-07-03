using System;
using System.Collections.Generic;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Xunit;
using System.IO;

namespace Rasp.Core.Tests.Engine;

public class CommandInjectionDetectionEngineTests
{
    private CommandInjectionDetectionEngine CreateEngine(List<string> allowedProcesses)
    {
        var options = new RaspOptions
        {
            AllowedProcesses = allowedProcesses
        };
        var optionsWrapper = Options.Create(options);
        return new CommandInjectionDetectionEngine(optionsWrapper);
    }

    [Fact]
    public void Inspect_EmptyAllowlist_BlocksEverything()
    {
        var engine = CreateEngine(new List<string>());
        var result = engine.Inspect("git", new[] { "status" }, false);

        result.IsThreat.Should().BeTrue();
        result.Description.Should().Contain("Empty Allowlist");
    }

    [Fact]
    public void Inspect_ExecutableInAllowlist_ReturnsSafe()
    {
        // Must use full paths or valid relative paths that resolve correctly in tests
        var currentDir = Directory.GetCurrentDirectory();
        var gitPath = Path.Combine(currentDir, "git");
        var dotnetPath = Path.Combine(currentDir, "dotnet.exe");

        var engine = CreateEngine(new List<string> { gitPath, dotnetPath });

        var result1 = engine.Inspect(gitPath, new[] { "status" }, false);
        var result2 = engine.Inspect(dotnetPath, new[] { "--version" }, false);

        result1.IsThreat.Should().BeFalse();
        result2.IsThreat.Should().BeFalse();
    }

    [Fact]
    public void Inspect_ExecutableNotInAllowlist_ReturnsThreat()
    {
        var currentDir = Directory.GetCurrentDirectory();
        var gitPath = Path.Combine(currentDir, "git");
        var cmdPath = Path.Combine(currentDir, "cmd.exe");

        var engine = CreateEngine(new List<string> { gitPath });

        var result = engine.Inspect(cmdPath, new[] { "/c", "echo", "hello" }, false);

        result.IsThreat.Should().BeTrue();
        result.Description.Should().Contain("not in allowlist");
    }

    [Fact]
    public void Inspect_ExecutableAllowed_ButArgumentsContainMetacharacter_WithShellExecute_ReturnsThreat()
    {
        var currentDir = Directory.GetCurrentDirectory();
        var bashPath = Path.Combine(currentDir, "bash");

        var engine = CreateEngine(new List<string> { bashPath });

        // Even if useShellExecute is false, bash is a shell interpreter, so it should block
        var result = engine.Inspect(bashPath, new[] { "-c", "ls & rm -rf /" }, false);

        result.IsThreat.Should().BeTrue();
        result.Description.Should().Contain("Dangerous shell metacharacter");
    }

    [Fact]
    public void Inspect_SpoofedExecutableNameInDifferentDirectory_ReturnsThreat()
    {
        // This tests the exact bypass: allowlist says /usr/bin/git
        // Attacker runs /tmp/git
        // If we only checked Path.GetFileName, it would bypass.
        // Because we canonicalize and match the full path, it should be blocked.
        var allowedGitPath = Path.Combine(Directory.GetCurrentDirectory(), "usr", "bin", "git");
        var maliciousGitPath = Path.Combine(Directory.GetCurrentDirectory(), "tmp", "git");

        var engine = CreateEngine(new List<string> { allowedGitPath });

        var result = engine.Inspect(maliciousGitPath, new[] { "status" }, false);

        result.IsThreat.Should().BeTrue();
        result.Description.Should().Contain("not in allowlist");
    }
}
