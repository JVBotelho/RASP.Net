using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Rasp.Bootstrapper;

namespace Rasp.Core.Tests.DependencyInjection;

/// <summary>
/// Verifies the integrity of the Dependency Injection (DI) container configuration.
/// Ensures that all services and their dependencies are correctly registered and compatible.
/// </summary>
public class DiSanityTests
{
    /// <summary>
    /// Ensures that <see cref="RaspDependencyInjection.AddRasp"/> registers all required services 
    /// without missing dependencies or causing scope violations.
    /// </summary>
    [Fact]
    public void AddRasp_Should_Register_All_Dependencies_Correctly()
    {
        // 1. Arrange
        var services = new ServiceCollection();

        var config = new ConfigurationBuilder().Build();

        services.AddSingleton<IConfiguration>(config);
        services.AddLogging();

        services.AddGrpc();

        // 2. Act
        services.AddRasp(config);

        var options = new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        };

        Action build = () => services.BuildServiceProvider(options);

        build.Should().NotThrow("the RASP dependency graph must be complete and valid");
    }
}