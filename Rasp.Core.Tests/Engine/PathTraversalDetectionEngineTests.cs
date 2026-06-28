using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Rasp.Core.Configuration;
using Rasp.Core.Engine;
using Xunit;

namespace Rasp.Core.Tests.Engine;

public class PathTraversalDetectionEngineTests
{
    private PathTraversalDetectionEngine CreateEngine(List<string> allowedRoots)
    {
        var options = new RaspOptions
        {
            AllowedFileRoots = allowedRoots
        };
        var optionsWrapper = Options.Create(options);
        return new PathTraversalDetectionEngine(optionsWrapper);
    }

    [Fact]
    public void Inspect_NoRootsConfigured_ReturnsSafe()
    {
        var engine = CreateEngine(new List<string>());
        var result = engine.Inspect("/etc/passwd");
        
        result.IsThreat.Should().BeFalse();
    }

    [Fact]
    public void Inspect_WithinAllowedRoot_ReturnsSafe()
    {
        var root = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "C:\\App\\Data" : "/app/data";
        var engine = CreateEngine(new List<string> { root });
        
        var path = Path.Combine(root, "file.txt");
        var result = engine.Inspect(path);
        
        result.IsThreat.Should().BeFalse();
    }

    [Fact]
    public void Inspect_OutsideAllowedRoot_ReturnsThreat()
    {
        var root = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "C:\\App\\Data" : "/app/data";
        var engine = CreateEngine(new List<string> { root });
        
        var path = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "C:\\Windows\\System32\\sam" : "/etc/passwd";
        var result = engine.Inspect(path);
        
        result.IsThreat.Should().BeTrue();
        result.ThreatType.Should().Be("Path Traversal");
    }

    [Fact]
    public void Inspect_TraversalAttempt_EscapingRoot_ReturnsThreat()
    {
        var root = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "C:\\App\\Data" : "/app/data";
        var engine = CreateEngine(new List<string> { root });
        
        // Starts in allowed root but escapes using ../
        var path = Path.Combine(root, "..", "..", "Windows", "System32", "sam");
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            path = Path.Combine(root, "..", "..", "etc", "passwd");
        }

        var result = engine.Inspect(path);
        
        result.IsThreat.Should().BeTrue();
        result.MatchedPattern.Should().NotContain(".."); // Match pattern should be the fully resolved path
    }

    [Fact]
    public void Inspect_TraversalAttempt_StayingWithinRoot_ReturnsSafe()
    {
        var root = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "C:\\App\\Data" : "/app/data";
        var engine = CreateEngine(new List<string> { root });
        
        var path = Path.Combine(root, "subdir", "..", "file.txt");
        var result = engine.Inspect(path);
        
        result.IsThreat.Should().BeFalse();
    }

    [Fact]
    public void Inspect_PrefixBypass_ReturnsThreat()
    {
        // Tests the boundary fix (StartsWith bug)
        var root = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "C:\\App\\Data" : "/app/data";
        var engine = CreateEngine(new List<string> { root });
        
        // This starts with the same string, but is a different directory!
        var bypassPath = root + "-secret";
        
        var path = Path.Combine(bypassPath, "file.txt");
        var result = engine.Inspect(path);
        
        result.IsThreat.Should().BeTrue();
    }
}
