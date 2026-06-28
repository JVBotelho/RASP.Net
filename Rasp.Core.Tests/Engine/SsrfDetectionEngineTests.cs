using System;
using System.Net;
using Rasp.Core.Engine;
using Xunit;

namespace Rasp.Core.Tests.Engine;

public class SsrfDetectionEngineTests
{
    private readonly SsrfDetectionEngine _engine;

    public SsrfDetectionEngineTests()
    {
        _engine = new SsrfDetectionEngine(null!);
    }

    [Fact]
    public void Inspect_Uri_WithDangerousScheme_ReturnsThreat()
    {
        var result = _engine.Inspect(new Uri("file:///etc/passwd"));
        Assert.True(result.IsThreat);
        Assert.Equal("DangerousScheme", result.MatchedPattern);
    }

    [Fact]
    public void Inspect_String_WithObfuscatedIp_ReturnsThreat()
    {
        // 2852039166 in decimal is 169.254.169.254 (IMDS)
        var result = _engine.Inspect("http://2852039166/");
        Assert.True(result.IsThreat);
        Assert.Equal("LinkLocal", result.MatchedPattern);
    }

    [Theory]
    [InlineData("127.0.0.1", "LoopbackAccess")]
    [InlineData("::1", "LoopbackAccess")]
    [InlineData("::ffff:127.0.0.1", "LoopbackAccess")]
    [InlineData("0.0.0.0", "WildcardIP")]
    [InlineData("::", "WildcardIP")]
    [InlineData("::ffff:0.0.0.0", "WildcardIP")]
    [InlineData("169.254.169.254", "LinkLocal")]
    [InlineData("100.100.100.200", "AlibabaIMDS")]
    [InlineData("::ffff:100.100.100.200", "AlibabaIMDS")]
    [InlineData("fc00::1", "UniqueLocal")]
    public void Inspect_IPAddress_WithRestrictedRanges_ReturnsThreat(string ipString, string expectedPattern)
    {
        var ip = IPAddress.Parse(ipString);
        var result = _engine.Inspect(ip);
        
        Assert.True(result.IsThreat);
        Assert.Equal(expectedPattern, result.MatchedPattern);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("2606:4700:4700::1111")]
    public void Inspect_IPAddress_WithSafeRanges_ReturnsSafe(string ipString)
    {
        var ip = IPAddress.Parse(ipString);
        var result = _engine.Inspect(ip);
        
        Assert.False(result.IsThreat);
    }
}
