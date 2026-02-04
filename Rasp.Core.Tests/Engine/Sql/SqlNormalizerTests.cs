using Rasp.Core.Engine.Sql;

namespace Rasp.Core.Tests.Engine.Sql;

public class SqlNormalizerTests
{
    [Fact]
    public void Normalize_WithSmallBuffer_ShouldTruncateAndNotThrow()
    {
        // Arrange
        const string input = "SELECT * FROM Users WHERE id = 1"; // Length 32
        Span<char> smallBuffer = stackalloc char[10];   // Only 10 chars capacity

        // Act
        // This should strictly fill only 10 chars and return 10, no IndexOutOfRangeException
        int written = SqlNormalizer.Normalize(input, smallBuffer);
        string result = smallBuffer[..written].ToString();

        // Assert
        Assert.Equal(10, written);
        Assert.Equal("select * f", result); // Truncated result
    }
}