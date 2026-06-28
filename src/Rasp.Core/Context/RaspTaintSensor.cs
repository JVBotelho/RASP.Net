using System.Runtime.CompilerServices;

namespace Rasp.Core.Context;

/// <summary>
/// Managed taint-tracking sensor for ADR-006 Phase C (native CLR profiler).
/// <para>
/// Mark and check are plain managed method calls from code RASP already owns
/// (the source-generated <c>{Service}RaspInterceptor</c>, registered via
/// <c>AddRaspSecurity()</c> - not <c>SecurityInterceptor</c>, a generic fallback used only by
/// benchmarks; and <c>RaspContextMiddleware</c> mark; <c>SqlSinkGuard</c> checks) - no IL
/// rewriting is needed for those. <see cref="PropagateTaint"/> is the one
/// method the native profiler calls, injected via <c>CEE_CALL</c> against an
/// <c>mdMemberRef</c> resolved by <c>Rasp.Native.Profiler</c> into a small, curated set of
/// BCL string-producing methods (v1: <c>System.String::Concat(string, string)</c>) - see
/// docs/ADR/006-sink-instrumentation-strategy.md, "Addendum: native implementation design
/// notes", point 4.
/// </para>
/// <para>
/// Taint is tracked out-of-band, keyed by string *instance identity* via
/// <see cref="ConditionalWeakTable{TKey,TValue}"/> - the BCL-idiomatic way to attach
/// metadata to an immutable object without modifying it. Entries are collected
/// automatically once the tainted string itself becomes unreachable; there is nothing to
/// clean up manually.
/// </para>
/// <para>
/// A single process-wide table is intentional, not a bug: object identity alone already
/// disambiguates between requests (two concurrent requests never share the same string
/// instance), so there is no need to partition this by <see cref="RaspContext"/>.
/// </para>
/// </summary>
public static class RaspTaintSensor
{
    // Any non-null sentinel works as the table value - only presence/absence of the key
    // (the tainted string instance) matters.
    private static readonly object TaintedMarker = new();

    private static readonly ConditionalWeakTable<string, object> TaintedStrings = new();

    /// <summary>
    /// Marks <paramref name="value"/> as tainted (attacker-influenced). Called from a
    /// perimeter source once per piece of untrusted input - e.g. a gRPC request field or an
    /// HTTP request value.
    /// </summary>
    public static void MarkTainted(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        TaintedStrings.AddOrUpdate(value, TaintedMarker);
    }

    /// <summary>
    /// Returns true if <paramref name="value"/> is the same string instance (or was derived
    /// from one, via <see cref="PropagateTaint"/>) as something previously marked tainted.
    /// Called from a sink guard before it decides how much to trust ground-truth data that
    /// is otherwise indistinguishable from operator-supplied configuration.
    /// </summary>
    public static bool IsTainted(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        return TaintedStrings.TryGetValue(value, out _);
    }

    /// <summary>
    /// Called by the native profiler's injected probe after a curated BCL string-producing
    /// method returns. If either operand is tainted, the result is marked tainted too -
    /// this is what keeps a taint mark alive across a transformation that would otherwise
    /// silently create an untracked new string instance (strings are immutable; a
    /// concatenation result is never the same object as either operand).
    /// <para>
    /// v1 signature is fixed at two operands to match the sole v1 instrumentation target,
    /// <c>System.String::Concat(string, string)</c> (see RaspProfiler.cpp). Widening this
    /// to more BCL methods means widening this method's signature (or adding overloads) and
    /// updating the matching <c>mdMemberRef</c> signature blob on the native side in
    /// lockstep - the two must always agree byte-for-byte.
    /// </para>
    /// </summary>
    public static void PropagateTaint(string? result, string? arg0, string? arg1)
    {
        if (string.IsNullOrEmpty(result))
        {
            return;
        }

        if (IsTainted(arg0) || IsTainted(arg1))
        {
            MarkTainted(result);
        }
    }
}
