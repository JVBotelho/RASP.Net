using System;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Rasp.Core;
using Rasp.Core.Guard;

namespace Rasp.Instrumentation.SystemTextJson;

public static class RaspSystemTextJsonExtensions
{
    /// <summary>
    /// Registers the System.Text.Json RASP instrumentation dependencies.
    /// </summary>
    public static IServiceCollection AddRaspSystemTextJson(this IServiceCollection services)
    {
        services.AddRaspCore();
        return services;
    }

    /// <summary>
    /// Wires the RASP Insecure Deserialization protection into the provided JsonSerializerOptions.
    /// Hooks into the TypeInfoResolver to block known gadget chains at runtime.
    /// </summary>
    public static JsonSerializerOptions AddRaspProtection(this JsonSerializerOptions options, IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        var guard = serviceProvider.GetRequiredService<DeserializationGuard>();
        var modifierAction = RaspJsonTypeInfoModifier.CreateModifier(guard);
        
        if (options.TypeInfoResolver is DefaultJsonTypeInfoResolver defaultResolver)
        {
            defaultResolver.Modifiers.Add(modifierAction);
        }
        else if (options.TypeInfoResolver == null)
        {
            var resolver = new DefaultJsonTypeInfoResolver();
            resolver.Modifiers.Add(modifierAction);
            options.TypeInfoResolver = resolver;
        }
        else
        {
            // If they are using a custom resolver, we can't safely inject modifiers without overriding it.
            // In .NET 8+, you can chain resolvers, but the modifier approach is standard for DefaultJsonTypeInfoResolver.
            throw new NotSupportedException("AddRaspProtection requires the TypeInfoResolver to be null or a DefaultJsonTypeInfoResolver.");
        }

        return options;
    }
}
