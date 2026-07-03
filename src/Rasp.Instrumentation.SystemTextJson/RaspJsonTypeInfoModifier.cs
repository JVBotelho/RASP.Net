using System.Text.Json.Serialization.Metadata;
using Rasp.Core.Guard;

namespace Rasp.Instrumentation.SystemTextJson;

public static class RaspJsonTypeInfoModifier
{
    /// <summary>
    /// Creates a modifier action for System.Text.Json type info resolution.
    /// This will inspect every Type being resolved during deserialization 
    /// and block known dangerous gadget chains.
    /// </summary>
    public static System.Action<JsonTypeInfo> CreateModifier(DeserializationGuard guard)
    {
        return jsonTypeInfo =>
        {
            // Analyze the Type to ensure it's not a known dangerous gadget
            guard.AnalyzeType(jsonTypeInfo.Type, "System.Text.Json");
        };
    }
}
