using System.Reflection;
using Google.Protobuf;
using Rasp.Core.Abstractions;
using Rasp.Core.Models;

namespace Rasp.Benchmarks;

public class RecursiveReflectionInspector : IGrpcMessageInspector
{
    // Cache de propriedades para não ser TÃO lento (seria injusto não usar cache)
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, PropertyInfo[]> _cache = new();

    public DetectionResult Inspect(IMessage message, IDetectionEngine engine, int maxScanChars)
    {
        ArgumentNullException.ThrowIfNull(engine);
        return ScanRecursive(message, engine, 0);
    }

    private DetectionResult ScanRecursive(object obj, IDetectionEngine engine, int depth)
    {
        if (obj == null || depth > 15) return DetectionResult.Safe();

        var type = obj.GetType();

        // Pega do cache ou reflete
        var props = _cache.GetOrAdd(type, t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance));

        foreach (var prop in props)
        {
            if (prop.PropertyType == typeof(string))
            {
                var value = (string?)prop.GetValue(obj);
                if (!string.IsNullOrEmpty(value))
                {
                    // Scan com contexto
                    var res = engine.Inspect(value.AsSpan(), prop.Name);
                    if (res.IsThreat) return res;
                }
            }
            // Se for um tipo complexo (exceto string), desce o nível
            else if (prop.PropertyType.IsClass && prop.PropertyType != typeof(string))
            {
                var nestedObj = prop.GetValue(obj);
                if (nestedObj != null)
                {
                    var res = ScanRecursive(nestedObj, engine, depth + 1);
                    if (res.IsThreat) return res;
                }
            }
        }

        return DetectionResult.Safe();
    }
}