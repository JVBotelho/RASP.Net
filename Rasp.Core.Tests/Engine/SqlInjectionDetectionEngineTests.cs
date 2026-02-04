using Microsoft.Extensions.Logging.Abstractions;
using Rasp.Core.Engine;
using Rasp.Core.Models;

namespace Rasp.Core.Tests;

public class SqlInjectionDetectionEngineTests
{
    private readonly SqlInjectionDetectionEngine _sut; // System Under Test

    public SqlInjectionDetectionEngineTests()
    {
        _sut = new SqlInjectionDetectionEngine(NullLogger<SqlInjectionDetectionEngine>.Instance);
    }

    [Theory]
    [InlineData("O'Reilly")]
    [InlineData("D'Angelo")]
    [InlineData("L'oreal")]
    [InlineData("McDonald's")]
    [InlineData("Grand'Mère")]
    public void Inspect_ShouldNotFlag_LegitimateNamesWithApostrophes(string safeInput)
    {
        // Act
        var result = _sut.Inspect(safeInput);

        // Assert
        Assert.False(result.IsThreat, $"Falso positivo detectado! O nome legítimo '{safeInput}' foi bloqueado.");
    }

    [Theory]
    [InlineData("admin' OR '1'='1")]
    [InlineData("user' UNION SELECT")]
    [InlineData("name'; DROP TABLE users --")]
    public void Inspect_ShouldFlag_AttacksWithQuotes(string attackInput)
    {
        // Act
        var result = _sut.Inspect(attackInput);

        // Assert
        Assert.True(result.IsThreat, $"Falso negativo! O ataque '{attackInput}' passou despercebido.");
    }
}