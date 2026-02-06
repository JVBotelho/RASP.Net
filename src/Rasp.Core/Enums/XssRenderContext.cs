namespace Rasp.Core.Enums;

/// <summary>
/// Defines the rendering context where user input will be interpreted by the browser.
/// Critical for context-aware sanitization as described in the specification.
/// </summary>
public enum XssRenderContext
{
    /// <summary>
    /// Unknown or unspecified context. Uses most conservative rules.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// HTML Body context (e.g., between &lt;div&gt; tags).
    /// Dangerous: &lt;script&gt;, &lt;img onerror=, &lt;iframe&gt;
    /// </summary>
    HtmlBody = 1,

    /// <summary>
    /// HTML Attribute context (e.g., inside src="" or href="").
    /// Dangerous: javascript:, data:text/html, event handlers
    /// </summary>
    HtmlAttribute = 2,

    /// <summary>
    /// JavaScript context (e.g., inside &lt;script&gt; tags or event handlers).
    /// Dangerous: String escapes, comment injection, Unicode escapes
    /// </summary>
    JavaScript = 3,

    /// <summary>
    /// URI/URL context (e.g., href, src attributes).
    /// Dangerous: javascript:, data:, vbscript: protocols
    /// </summary>
    Uri = 4,

    /// <summary>
    /// CSS context (e.g., style attributes or &lt;style&gt; tags).
    /// Dangerous: expression(), url(javascript:...)
    /// </summary>
    Css = 5
}