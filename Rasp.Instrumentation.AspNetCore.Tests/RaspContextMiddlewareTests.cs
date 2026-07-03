using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Rasp.Core.Context;
using Rasp.Instrumentation.AspNetCore;
using Xunit;

namespace Rasp.Instrumentation.AspNetCore.Tests;

public class RaspContextMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_MarksQueryStringValuesAsTainted()
    {
        var queryValue = "search-term-" + System.Guid.NewGuid();
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString($"?q={queryValue}");

        var middleware = new RaspContextMiddleware(_ => Task.CompletedTask);

        Assert.False(RaspTaintSensor.IsTainted(queryValue));

        await middleware.InvokeAsync(httpContext);

        // The middleware reads context.Request.Query["q"], which returns the same string
        // instance parsed from the query string above - assert on that instance directly,
        // matching how a downstream handler would actually read it.
        var parsedValue = httpContext.Request.Query["q"].ToString();
        Assert.True(RaspTaintSensor.IsTainted(parsedValue));
    }

    [Fact]
    public async Task InvokeAsync_EstablishesRaspContext_ForTheDurationOfNext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/books/search";
        httpContext.Request.Method = "GET";

        RaspContext? observedDuringNext = null;
        var middleware = new RaspContextMiddleware(_ =>
        {
            observedDuringNext = RaspExecutionContext.Current;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(httpContext);

        Assert.NotNull(observedDuringNext);
        Assert.Contains("/books/search", observedDuringNext!.Source);
        Assert.Null(RaspExecutionContext.Current); // scope restored after the middleware returns
    }

    [Fact]
    public async Task InvokeAsync_NoQueryString_DoesNotThrow()
    {
        var httpContext = new DefaultHttpContext();
        var middleware = new RaspContextMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(httpContext);
    }
}
