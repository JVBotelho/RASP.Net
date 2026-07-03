using System;
using System.Threading;

namespace Rasp.Core.Context;

/// <summary>
/// A disposable scope that restores the previous RaspContext when disposed.
/// </summary>
public readonly struct RaspScope : IDisposable, IEquatable<RaspScope>
{
    private readonly RaspContext? _previous;

    internal RaspScope(RaspContext? previous)
    {
        _previous = previous;
    }

    public void Dispose()
    {
        RaspExecutionContext.SetCurrent(_previous);
    }

    public override bool Equals(object? obj) => obj is RaspScope scope && Equals(scope);

    public bool Equals(RaspScope other) => _previous == other._previous;

    public override int GetHashCode() => _previous?.GetHashCode() ?? 0;

    public static bool operator ==(RaspScope left, RaspScope right) => left.Equals(right);

    public static bool operator !=(RaspScope left, RaspScope right) => !(left == right);
}
