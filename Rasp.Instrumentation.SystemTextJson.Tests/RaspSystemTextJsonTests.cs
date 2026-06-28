using System;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rasp.Core;
using Rasp.Core.Abstractions;
using Rasp.Core.Configuration;
using Rasp.Core.Exceptions;
using Rasp.Core.Guard;
using Rasp.Instrumentation.SystemTextJson;
using Xunit;

namespace Rasp.Instrumentation.SystemTextJson.Tests;

public class DummyRaspMetrics : IRaspMetrics
{
    public void RecordInspection(string layer, double durationMs) { }
    public void ReportThreat(string layer, string threatType, bool blocked) { }
}

public class RaspSystemTextJsonTests
{
    private DeserializationGuard CreateGuard(bool blockOnDetection = true)
    {
        var services = new ServiceCollection();
        
        var options = new RaspOptions { BlockOnDetection = blockOnDetection };
        services.AddSingleton(Options.Create(options));
        services.AddSingleton<IRaspMetrics, DummyRaspMetrics>();
        services.AddLogging();
        
        services.AddRaspCore();
        services.AddRaspSystemTextJson();
        
        var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<DeserializationGuard>();
    }

    private JsonSerializerOptions CreateOptions(bool blockOnDetection = true)
    {
        var guard = CreateGuard(blockOnDetection);
        
        var options = new JsonSerializerOptions
        {
            TypeInfoResolver = new DefaultJsonTypeInfoResolver
            {
                Modifiers = { RaspJsonTypeInfoModifier.CreateModifier(guard) }
            }
        };

        return options;
    }

    public class SafeType { public string? Name { get; set; } }

    [Fact]
    public void SafeType_ShouldDeserializeNormally()
    {
        var options = CreateOptions();
        var json = """{"Name":"Test"}""";

        var result = JsonSerializer.Deserialize<SafeType>(json, options);
        result.Should().NotBeNull();
        result!.Name.Should().Be("Test");
    }

    [Fact]
    public void DangerousType_ShouldThrowRaspSecurityException()
    {
        var options = CreateOptions(blockOnDetection: true);
        var json = "{}"; // Content doesn't matter, type resolution is blocked

        Action act = () => JsonSerializer.Deserialize<System.Diagnostics.Process>(json, options);

        act.Should().Throw<RaspSecurityException>()
           .WithMessage("*gadget chain*");
    }

    [Fact]
    public void DangerousNamespace_ShouldThrowRaspSecurityException()
    {
        var options = CreateOptions(blockOnDetection: true);
        var json = "{}";

        Action act = () => JsonSerializer.Deserialize<System.Reflection.Assembly>(json, options);

        act.Should().Throw<RaspSecurityException>()
           .WithMessage("*gadget chain*");
    }

    [Fact]
    public void AuditMode_ShouldNotThrow()
    {
        var options = CreateOptions(blockOnDetection: false);
        var json = "{}";

        // In System.Text.Json, attempting to deserialize Process directly 
        // usually throws NotSupportedException because it has no parameterless ctor 
        // or properties that can be set, but we want to make sure RaspSecurityException is NOT thrown.
        Action act = () => JsonSerializer.Deserialize<System.Diagnostics.Process>(json, options);

        act.Should().NotThrow<RaspSecurityException>();
    }
}
