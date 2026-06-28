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
    // Operand pairs not on any fixed enumerated list - the generic same-operand check
    // (HasTautology) must catch these the same way it catches the ones above, since a
    // literal-list-only implementation would let any operand not explicitly enumerated
    // straight through.
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR 2=2")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR 'x'='x'")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR \"x\"=\"x\"")]
    [InlineData("SELECT * FROM Users WHERE Id = 1 OR Id=Id")]
    public void Inspect_ShouldDetect_Tautology(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue();
        result.MatchedPattern.Should().Be("Tautology");
    }

    [Theory]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR 5>1")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a' OR 1 BETWEEN 1 AND 9")]
    public void Inspect_ShouldNotFlag_NonEqualityTautology_KnownGap(string payload)
    {
        // Documented residual gap (see SqlSinkDetectionEngine's class doc): the generic
        // check is scoped to same-operand equality, not full constant folding of
        // inequalities/BETWEEN. This test pins the current (accepted) behavior so a future
        // change doesn't silently start blocking these without a deliberate decision.
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeFalse();
    }

    [Fact]
    public void Inspect_ShouldNotFlag_ColumnNamedAuthorEndingInOr()
    {
        // "or " word-boundary check must not false-match inside identifiers.
        var result = _sut.Inspect("SELECT Author FROM Books WHERE Author = 'Tolkien'");
        result.IsThreat.Should().BeFalse();
    }

    [Theory]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; DROP TABLE Users")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; ALTER TABLE Users DROP COLUMN Name")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; TRUNCATE TABLE Users")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; EXEC xp_cmdshell 'dir'")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; WAITFOR DELAY '0:0:5'")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; GRANT ALL ON Users TO public")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; REVOKE SELECT ON Users FROM public")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; SHUTDOWN")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; CREATE TABLE Evil (x int)")]
    [InlineData("SELECT * FROM Users WHERE Name = 'a'; MERGE INTO Users USING (SELECT 1) AS s ON 1=1 WHEN MATCHED THEN DELETE")]
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
