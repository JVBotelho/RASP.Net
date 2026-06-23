using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Rasp.Core.Engine;
using Xunit;

namespace Rasp.Instrumentation.EntityFrameworkCore.Tests;

public class SqlSinkDetectionEngineTests
{
    private readonly SqlSinkDetectionEngine _sut = new();

    [Theory]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR 1=1")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR '1'='1'")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR ''=''")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR \"\"=\"\"")]
    public void Inspect_ShouldDetect_Tautology(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue();
        result.MatchedPattern.Should().Be("Tautology");
    }

    [Theory]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; DROP TABLE Users")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; ALTER TABLE Users DROP COLUMN Name")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; TRUNCATE TABLE Users")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; EXEC xp_cmdshell 'dir'")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; WAITFOR DELAY '0:0:5'")]
    public void Inspect_ShouldDetect_DangerousStackedQuery(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue();
        result.MatchedPattern.Should().Be("StackedQuery");
    }

    [Theory]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' -- comment")] // Has non-whitespace before --
    public void Inspect_ShouldDetect_CommentBreakout(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue();
        result.MatchedPattern.Should().Be("CommentBreakout");
    }

    [Theory]
    [InlineData("INSERT INTO Users (Name) VALUES ('a'); INSERT INTO Users (Name) VALUES ('b'); SELECT * FROM Users")]
    [InlineData("UPDATE Users SET Name = 'b' WHERE Name = 'a'; DELETE FROM Users WHERE Name = 'c'")]
    public void Inspect_ShouldNotFlag_NormalEfBatching(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeFalse();
    }

    [Theory]
    [InlineData("-- tag\nSELECT * FROM Users")]
    [InlineData("  -- tag\nSELECT * FROM Users")]
    [InlineData("SELECT * FROM Users")]
    public void Inspect_ShouldNotFlag_EfTagWith(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeFalse();
    }
}
