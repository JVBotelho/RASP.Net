using System.Threading;

namespace Rasp.Core.Context;

public static class RaspExecutionContext
{
    private static readonly AsyncLocal<RaspContext?> _current = new();

    public static RaspContext? Current => _current.Value;

    internal static void SetCurrent(RaspContext? context)
    {
        _current.Value = context;
    }

    /// <summary>Establish context at a source. Returns a scope that clears it on dispose.</summary>
    public static RaspScope BeginScope(RaspContext context)
    {
        var previous = _current.Value;
        _current.Value = context;
        return new RaspScope(previous);
    }
}
