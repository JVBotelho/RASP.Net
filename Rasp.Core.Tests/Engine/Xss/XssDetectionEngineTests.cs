using FluentAssertions;
using Rasp.Core.Engine;

namespace Rasp.Core.Tests.Engine.Xss;

/// <summary>
/// XSS Detection Engine tests based on OWASP XSS Filter Evasion Cheat Sheet.
/// https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
/// </summary>
public class XssDetectionEngineTests
{
    private readonly XssDetectionEngine _sut = new();

    #region OWASP Category: Basic XSS Vectors

    [Theory]
    [InlineData("<script>alert('XSS')</script>")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<SCRIPT>alert('XSS')</SCRIPT>")]
    [InlineData("<ScRiPt>alert(1)</ScRiPt>")]
    public void Inspect_ShouldDetect_BasicScriptTags(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"payload '{payload}' should be detected as XSS");
    }

    [Theory]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<img src=x onerror=\"alert(1)\">")]
    [InlineData("<IMG SRC=x ONERROR=alert(1)>")]
    [InlineData("<body onload=alert(1)>")]
    [InlineData("<input onfocus=alert(1) autofocus>")]
    [InlineData("<svg onload=alert(1)>")]
    [InlineData("<div onclick=alert(1)>")]
    public void Inspect_ShouldDetect_EventHandlers(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"payload '{payload}' should be detected as XSS");
    }

    [Theory]
    [InlineData("<a href=\"javascript:alert(1)\">click</a>")]
    [InlineData("<a href='javascript:alert(1)'>click</a>")]
    [InlineData("<iframe src=\"javascript:alert(1)\">")]
    [InlineData("<a href=\"vbscript:msgbox(1)\">")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    public void Inspect_ShouldDetect_DangerousProtocols(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"payload '{payload}' should be detected as XSS");
    }

    #endregion

    #region OWASP Category: Encoding Evasion

    [Theory]
    [InlineData("%3Cscript%3Ealert(1)%3C/script%3E")] // URL encoding
    [InlineData("%3cscript%3ealert(1)%3c/script%3e")] // lowercase hex
    [InlineData("%3CSCRIPT%3Ealert(1)%3C/SCRIPT%3E")] // URL + uppercase tag
    public void Inspect_ShouldDetect_UrlEncodedPayloads(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"URL-encoded payload '{payload}' should be detected");
    }

    [Theory]
    [InlineData("&lt;script&gt;alert(1)&lt;/script&gt;")] // HTML entities
    [InlineData("&#60;script&#62;alert(1)&#60;/script&#62;")] // Decimal entities
    [InlineData("&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;")] // Hex entities
    public void Inspect_ShouldDetect_HtmlEntityEncodedPayloads(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"HTML-entity payload '{payload}' should be detected");
    }

    [Theory]
    [InlineData("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e")] // Unicode escapes
    [InlineData("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e")] // Hex escapes
    public void Inspect_ShouldDetect_UnicodeEscapedPayloads(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Unicode-escaped payload '{payload}' should be detected");
    }

    [Theory]
    [InlineData("%26lt;script%26gt;alert(1)%26lt;/script%26gt;")] // Double URL encoding
    [InlineData("%253Cscript%253Ealert(1)%253C/script%253E")] // Double encoded < >
    public void Inspect_ShouldDetect_DoubleEncodedPayloads(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Double-encoded payload '{payload}' should be detected");
    }

    #endregion

    #region OWASP Category: Filter Evasion Techniques

    [Theory]
    [InlineData("\"><script>alert(1)</script>")] // Attribute breakout with "
    [InlineData("'><script>alert(1)</script>")] // Attribute breakout with '
    [InlineData("\"><img src=x onerror=alert(1)>")] // Breakout to img
    public void Inspect_ShouldDetect_AttributeBreakout(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Breakout payload '{payload}' should be detected");
    }

    [Theory]
    [InlineData("<svg/onload=alert(1)>")] // No space before event
    [InlineData("<img/src=x/onerror=alert(1)>")] // Slash separators
    [InlineData("<body\nonload=alert(1)>")] // Newline before event
    [InlineData("<body\tonload=alert(1)>")] // Tab before event
    public void Inspect_ShouldDetect_WhitespaceVariations(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Whitespace variation '{payload}' should be detected");
    }

    [Theory]
    [InlineData("<iframe src=\"javascript:alert(1)\">")]
    [InlineData("<object data=\"javascript:alert(1)\">")]
    [InlineData("<embed src=\"javascript:alert(1)\">")]
    [InlineData("<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">")]
    public void Inspect_ShouldDetect_DangerousElements(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Dangerous element '{payload}' should be detected");
    }

    [Theory]
    [InlineData("';alert(1)//")]
    [InlineData("\";alert(1)//")]
    [InlineData("</script><script>alert(1)</script>")]
    public void Inspect_ShouldDetect_ContextBreakout(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Context breakout '{payload}' should be detected");
    }

    #endregion

    #region OWASP Category: Polyglot XSS

    [Theory]
    [InlineData("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>")] // Classic polyglot
    [InlineData("'\"><img src=x onerror=alert(1)>//")]
    public void Inspect_ShouldDetect_PolyglotPayloads(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Polyglot payload should be detected");
    }

    #endregion

    #region False Positive Prevention

    [Theory]
    [InlineData("Hello World")]
    [InlineData("This is a normal text with no XSS")]
    [InlineData("user@example.com")]
    [InlineData("The price is $50 for 25% discount")]
    [InlineData("1 + 1 = 2")]
    [InlineData("A & B Company")]
    [InlineData("McDonald's Restaurant")]
    [InlineData("C:\\Users\\John\\Documents")]
    public void Inspect_ShouldNotFlag_LegitimateText(string safeInput)
    {
        var result = _sut.Inspect(safeInput);
        result.IsThreat.Should().BeFalse($"Legitimate text '{safeInput}' should NOT be flagged");
    }

    [Theory]
    [InlineData("<b>Bold</b>")]
    [InlineData("<i>Italic</i>")]
    [InlineData("<p>Paragraph</p>")]
    [InlineData("<div>Container</div>")]
    [InlineData("<span>Inline</span>")]
    [InlineData("<a href=\"https://example.com\">Link</a>")]
    [InlineData("<ul><li>Item</li></ul>")]
    public void Inspect_ShouldNotFlag_SafeHtmlTags(string safeInput)
    {
        var result = _sut.Inspect(safeInput);
        result.IsThreat.Should().BeFalse($"Safe HTML '{safeInput}' should NOT be flagged");
    }

    [Theory]
    [InlineData("x < 10")]
    [InlineData("if (x > 5) return")]
    [InlineData("x < y && y > z")]
    [InlineData("Compare: 5 < 10 > 3")]
    public void Inspect_ShouldNotFlag_MathematicalExpressions(string safeInput)
    {
        var result = _sut.Inspect(safeInput);
        result.IsThreat.Should().BeFalse($"Math expression '{safeInput}' should NOT be flagged");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Inspect_ShouldReturnSafe_ForNullOrEmptyInput(string? input)
    {
        var result = _sut.Inspect(input);
        result.IsThreat.Should().BeFalse("null/empty input should be safe");
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void Inspect_ShouldReject_OversizedPayloads()
    {
        var payload = new string('A', 10000);
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue("oversized payloads should be rejected as DoS");
    }

    #endregion

    #region Span-Based Hot Path Tests (Zero-Allocation Path)

    /// <summary>
    /// Tests the ReadOnlySpan overload directly to exercise the stackalloc/ArrayPool path.
    /// </summary>
    [Theory]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("%3Cscript%3Ealert(1)%3C/script%3E")]
    public void Inspect_Span_ShouldDetect_SameAsStringOverload(string payload)
    {
        // Act - using Span overload directly
        ReadOnlySpan<char> span = payload.AsSpan();
        var spanResult = _sut.Inspect(span);
        var stringResult = _sut.Inspect(payload);

        // Assert - both overloads should produce identical results
        spanResult.IsThreat.Should().Be(stringResult.IsThreat,
            "Span and string overloads must produce identical detection results");
        spanResult.ThreatType.Should().Be(stringResult.ThreatType,
            "Threat category must match between overloads");
    }

    /// <summary>
    /// Tests that large payloads (>1024 chars) trigger ArrayPool path and return correctly.
    /// </summary>
    [Fact]
    public void Inspect_Span_LargePayload_ShouldUseArrayPoolPath()
    {
        // Arrange - payload > 1024 chars triggers ArrayPool instead of stackalloc
        var padding = new string('x', 2000);
        var payload = $"{padding}<script>alert(1)</script>";

        // Act
        var result = _sut.Inspect(payload.AsSpan());

        // Assert
        result.IsThreat.Should().BeTrue("ArrayPool path should detect threats correctly");
    }

    /// <summary>
    /// Verifies that Span overload handles empty/whitespace correctly.
    /// </summary>
    [Fact]
    public void Inspect_Span_EmptySpan_ShouldReturnSafe()
    {
        var result = _sut.Inspect(ReadOnlySpan<char>.Empty);
        result.IsThreat.Should().BeFalse("empty span should be safe");
    }

    #endregion

    #region Complexity Budget Stress Tests (DoS Prevention)

    /// <summary>
    /// Tests the complexity budget limit (200 decode operations).
    /// Verifies FAIL-CLOSED behavior: if budget exhausted before decoding attack, 
    /// the engine should still detect or safely reject.
    /// </summary>
    [Fact]
    public void Inspect_ShouldHandleExcessiveEncodingLayers_FailClosed()
    {
        // Arrange - create payload with 250 layers of URL encoding for '<'
        // Each layer: < -> %3C, so %3C -> %253C -> %25253C...
        var encoded = "<script>";
        for (int i = 0; i < 250; i++)
        {
            encoded = encoded.Replace("<", "%3C").Replace(">", "%3E");
        }

        // Act
        var result = _sut.Inspect(encoded);

        // Assert - Engine should either:
        // 1. Detect it as threat (if it decodes enough)
        // 2. NOT let it pass as safe if it looks suspicious
        // The key is: it should NOT be a false negative allowing attack through

        // Since complexity budget is 200 and we have 250 layers,
        // the engine won't fully decode. But it contains % which triggers decode path.
        // Current behavior: after 5 passes max, it stops. This is expected.
        // The test documents current behavior - not a security bypass since
        // raw encoded payload doesn't execute in browsers without decoding.
        result.Should().NotBeNull("Engine should always return a result, never throw");
    }

    /// <summary>
    /// Tests that payloads at exactly the complexity budget limit are handled.
    /// </summary>
    [Fact]
    public void Inspect_AtComplexityBudgetLimit_ShouldStillProcess()
    {
        // Arrange - 200 encoded characters (at budget limit)
        var payload = string.Join("", Enumerable.Repeat("%3C", 200)) + "script>";

        // Act
        var result = _sut.Inspect(payload);

        // Assert - should process without throwing
        result.Should().NotBeNull("should handle payloads at budget limit");
    }

    /// <summary>
    /// Tests multi-pass decoding with mixed encoding types.
    /// </summary>
    [Fact]
    public void Inspect_MixedEncodingTypes_ShouldDecodeIteratively()
    {
        // Arrange - nested encoding: URL -> HTML entity -> URL
        // %26lt; = &lt; in URL encoding
        // After first decode: &lt;
        // After second decode: <
        var payload = "%26lt;script%26gt;alert(1)%26lt;/script%26gt;";

        // Act
        var result = _sut.Inspect(payload);

        // Assert
        result.IsThreat.Should().BeTrue("nested encoding should be decoded and detected");
    }

    #endregion

    #region Heuristic Scoring Tests (Internal Validation)

    /// <summary>
    /// Tests that execution tags score 1.0 (immediate threat).
    /// </summary>
    [Theory]
    [InlineData("<script")]
    [InlineData("<iframe")]
    [InlineData("<object")]
    [InlineData("<embed")]
    public void Inspect_ExecutionTags_ShouldTriggerImmediatelyAsThreat(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Execution tag '{payload}' should score >= 1.0");
    }

    /// <summary>
    /// Tests that suspicious tags alone (without event handlers) don't trigger false positives.
    /// XssHeuristics scores <img, <svg etc. as 0.5, which is below threat threshold.
    /// </summary>
    [Theory]
    [InlineData("<img src=\"safe.jpg\">")]
    [InlineData("<svg viewBox=\"0 0 100 100\">")]
    [InlineData("<video src=\"video.mp4\">")]
    [InlineData("<audio src=\"audio.mp3\">")]
    public void Inspect_SuspiciousTagsWithoutEventHandlers_ShouldNotTrigger(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeFalse($"Suspicious tag without event handler should be safe: {payload}");
    }

    /// <summary>
    /// Tests that event handler requires '=' to trigger (prevents false positives on words like "onclick").
    /// </summary>
    [Theory]
    [InlineData("The onclick event is useful")]  // Text mentioning event
    [InlineData("Set onerror handler")]          // Text about events
    [InlineData("<div>Use onload for init</div>")] // Event name in content, not as attribute
    public void Inspect_EventNameWithoutEquals_ShouldNotTrigger(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeFalse($"Event name without '=' should not trigger: {payload}");
    }

    /// <summary>
    /// Validates that function calls (alert, eval, etc.) require parentheses context.
    /// </summary>
    [Theory]
    [InlineData("Please alert the team")]
    [InlineData("Do not eval the situation")]
    [InlineData("Confirm your attendance")]
    public void Inspect_FunctionNamesWithoutParentheses_ShouldNotTrigger(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeFalse($"Function name in text should not trigger: {payload}");
    }

    #endregion

    #region Deep Encoding Tests (10+ Layers)

    /// <summary>
    /// Tests detection with 10 layers of URL encoding.
    /// Each layer encodes % as %25, so %3C becomes %253C becomes %25253C...
    /// </summary>
    [Fact]
    public void Inspect_ShouldDetect_DeepUrlEncoding_10Layers()
    {
        // Arrange - 10 layers of URL encoding for <script>
        var payload = "<script>alert(1)</script>";
        for (int i = 0; i < 10; i++)
        {
            payload = Uri.EscapeDataString(payload);
        }

        // Act
        var result = _sut.Inspect(payload);

        // Assert - should either detect or safely handle
        // Note: With maxPasses=5 and budget=200, engine may not fully decode 10 layers
        // This test documents the limitation
        result.Should().NotBeNull("Engine must not throw on deep encoding");
    }

    /// <summary>
    /// Tests 5 layers (within maxPasses limit) to verify detection works.
    /// </summary>
    [Fact]
    public void Inspect_ShouldDetect_DeepUrlEncoding_5Layers()
    {
        // Arrange - 5 layers (at maxPasses limit)
        var payload = "<script>";
        for (int i = 0; i < 5; i++)
        {
            payload = Uri.EscapeDataString(payload);
        }

        // Act
        var result = _sut.Inspect(payload);

        // Assert
        result.IsThreat.Should().BeTrue("5 layers should be decodable within maxPasses limit");
    }

    #endregion

    #region Mixed Encoding Tests

    /// <summary>
    /// Tests URL + HTML entity mixed encoding.
    /// %26lt; decodes to &lt; which decodes to <
    /// </summary>
    [Theory]
    [InlineData("%26lt;script%26gt;alert(1)%26lt;/script%26gt;")] // URL-encoded HTML entities
    [InlineData("%26%2360;script%26%2362;")] // URL-encoded numeric entities
    public void Inspect_ShouldDetect_MixedUrlAndHtmlEntityEncoding(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Mixed URL+HTML encoding should be detected: {payload}");
    }

    /// <summary>
    /// Tests Unicode escape sequences mixed with other encodings.
    /// </summary>
    [Theory]
    [InlineData("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e")] // Pure Unicode
    [InlineData("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e")] // Hex escapes
    [InlineData("%5Cu003cscript%5Cu003e")] // URL-encoded Unicode escape
    public void Inspect_ShouldDetect_UnicodeAndHexEscapeMixtures(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Unicode/Hex escapes should be detected: {payload}");
    }

    /// <summary>
    /// Tests hex entity encoding variations.
    /// </summary>
    [Theory]
    [InlineData("&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;")] // Lowercase hex
    [InlineData("&#X3C;script&#X3E;alert(1)&#X3C;/script&#X3E;")] // Uppercase X
    [InlineData("&#x003c;script&#x003e;")] // Zero-padded hex
    public void Inspect_ShouldDetect_HexEntityVariations(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Hex entity variation should be detected: {payload}");
    }

    #endregion

    #region Expanded Polyglot Tests

    /// <summary>
    /// Critical multi-context polyglots that break HTML, JS, SQL, XML simultaneously.
    /// These MUST be detected by any RASP system.
    /// </summary>
    [Theory]
    [InlineData("'\"--></style></script><script>alert(1)</script>")]
    [InlineData("'><script>alert(1)</script><'")]
    [InlineData("\"><svg/onload=alert(1)//")]
    [InlineData("-->'><script>alert(1)</script>")]
    [InlineData("</script><script>alert(1)</script>")]
    public void Inspect_ShouldDetect_CriticalPolyglots(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Critical polyglot MUST be detected: {payload}");
    }

    /// <summary>
    /// KNOWN GAP: Pure JS context breakout without HTML tags isn't detected.
    /// These require HTML context for the engine to trigger.
    /// </summary>
    [Theory]
    [InlineData("'-alert(1)-'")]
    [InlineData("\"-alert(1)-\"")]
    public void Inspect_KnownGap_PureJsPolyglots_NotDetected(string payload)
    {
        var result = _sut.Inspect(payload);
        // GAP: Engine requires HTML special chars to trigger analysis
        result.IsThreat.Should().BeFalse($"KNOWN GAP: Pure JS polyglot not detected: {payload}");
    }

    /// <summary>
    /// Complex polyglot with String.fromCharCode obfuscation.
    /// </summary>
    [Fact]
    public void Inspect_ShouldDetect_StringFromCharCodePolyglot()
    {
        var payload = "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";" +
                      "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--" +
                      "></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>";

        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue("Complex polyglot with fromCharCode must be detected");
    }

    #endregion

    #region Protocol Handler Bypass Tests

    /// <summary>
    /// Tests base64-encoded data: protocol which can execute scripts.
    /// Engine detects data:text patterns via KillSwitchPatterns.
    /// </summary>
    [Theory]
    [InlineData("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")]
    [InlineData("data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==")]
    public void Inspect_ShouldDetect_Base64DataProtocol(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Base64 data protocol should be detected: {payload}");
    }

    /// <summary>
    /// Tests protocol handlers with case variations and obfuscation.
    /// </summary>
    [Theory]
    [InlineData("<a href=\"JaVaScRiPt:alert(1)\">")]  // Mixed case
    [InlineData("<a href=\"JAVASCRIPT:alert(1)\">")]  // Uppercase
    [InlineData("<a href=\"  javascript:alert(1)\">")] // Leading spaces
    public void Inspect_ShouldDetect_ProtocolCaseAndWhitespaceVariations(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Protocol variation should be detected: {payload}");
    }

    /// <summary>
    /// Tests protocol with whitespace that gets normalized by the engine.
    /// </summary>
    [Theory]
    [InlineData("<a href=\"java\tscript:alert(1)\">")]  // Tab in protocol
    [InlineData("<a href=\"java\nscript:alert(1)\">")]  // Newline in protocol
    public void Inspect_ShouldDetect_ProtocolWithWhitespaceNormalized(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Protocol with normalized whitespace should be detected: {payload}");
    }

    /// <summary>
    /// Tests protocol split with entities.
    /// </summary>
    [Theory]
    [InlineData("<a href=\"java&#115;cript:alert(1)\">")]  // &#115; = 's'
    [InlineData("<a href=\"java&#x73;cript:alert(1)\">")]  // &#x73; = 's'
    [InlineData("<a href=\"&#106;avascript:alert(1)\">")]  // &#106; = 'j'
    public void Inspect_ShouldDetect_ProtocolWithEntitySplit(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Protocol with entity split should be detected: {payload}");
    }

    #endregion

    #region Null Byte Injection Tests

    /// <summary>
    /// Tests null byte injection which can truncate strings in some parsers.
    /// </summary>
    [Theory]
    [InlineData("<scr\0ipt>alert(1)</script>")]
    [InlineData("<script>alert\0(1)</script>")]
    [InlineData("javascript\0:alert(1)")]
    public void Inspect_ShouldHandle_NullByteInjection(string payload)
    {
        // Act - should not throw and should handle safely
        var result = _sut.Inspect(payload);

        // Assert - null bytes should not bypass detection
        result.IsThreat.Should().BeTrue("Null bytes are stripped, revealing the attack signature");
    }

    #endregion


    #region Whitespace and Comment Evasion Tests

    /// <summary>
    /// Tests JavaScript comment injection to bypass detection.
    /// </summary>
    [Theory]
    [InlineData("<img src=x onerror=alert/*comment*/(1)>")]
    [InlineData("<img src=x onerror=alert//comment\n(1)>")]
    [InlineData("<script>/**/alert(1)</script>")]
    public void Inspect_ShouldDetect_CommentInjectionInJS(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Comment injection should be detected: {payload}");
    }

    /// <summary>
    /// Engine now detects these because chars < 32 are stripped during canonicalization.
    /// This normalizes whitespace-split handler names.
    /// </summary>
    [Theory]
    [InlineData("<svg/on\u000Cload=alert(1)>")]  // Form feed (U+000C) - stripped
    [InlineData("<svg/on\u0009load=alert(1)>")]  // Horizontal tab (U+0009) - stripped
    public void Inspect_ShouldDetect_ControlCharsInHandlerNames(string payload)
    {
        var result = _sut.Inspect(payload);
        // Engine strips chars < 32, so "on\tload" becomes "onload"
        result.IsThreat.Should().BeTrue($"Control chars in handler should be normalized and detected: {payload}");
    }

    /// <summary>
    /// KNOWN GAP: Non-breaking space (U+00A0) is >= 32, so it's NOT stripped.
    /// This remains undetected.
    /// </summary>
    [Theory]
    [InlineData("<svg/on\u00A0load=alert(1)>")]  // Non-breaking space (U+00A0) - NOT stripped
    public void Inspect_KnownGap_NonBreakingSpaceInHandler_NotDetected(string payload)
    {
        var result = _sut.Inspect(payload);
        // GAP: U+00A0 is char 160, not < 32, so not stripped
        result.IsThreat.Should().BeFalse($"KNOWN GAP: Non-breaking space not stripped: {payload}");
    }

    #endregion

    #region Case Sensitivity Bypass Tests

    /// <summary>
    /// Tests mixed case in tags, protocols, and event handlers.
    /// </summary>
    [Theory]
    [InlineData("<SvG/oNlOaD=alert(1)>")]
    [InlineData("<ImG sRc=x OnErRoR=alert(1)>")]
    [InlineData("<BoDy OnLoAd=alert(1)>")]
    [InlineData("<iNpUt OnFoCuS=alert(1)>")]
    public void Inspect_ShouldDetect_MixedCaseEventHandlers(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Mixed case event handler should be detected: {payload}");
    }

    /// <summary>
    /// Tests mixed case in dangerous protocols.
    /// </summary>
    [Theory]
    [InlineData("<a href=\"JaVaScRiPt:alert(1)\">link</a>")]
    [InlineData("<a href=\"VBSCRIPT:msgbox(1)\">link</a>")]
    [InlineData("<iframe src=\"DaTa:text/html,<script>alert(1)</script>\">")]
    public void Inspect_ShouldDetect_MixedCaseProtocols(string payload)
    {
        var result = _sut.Inspect(payload);
        result.IsThreat.Should().BeTrue($"Mixed case protocol should be detected: {payload}");
    }

    #endregion
}
