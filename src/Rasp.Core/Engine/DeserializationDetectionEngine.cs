using System;
using System.Collections.Generic;
using Rasp.Core.Abstractions;
using Rasp.Core.Models;
using Rasp.Core.Enums;

namespace Rasp.Core.Engine;

/// <summary>
/// A specialized detection engine for Insecure Deserialization.
/// Inspects type names or namespaces to block known gadget chains 
/// (e.g., ObjectDataProvider, AssemblyInstaller, Process) from being instantiated.
/// </summary>
public class DeserializationDetectionEngine : IDetectionEngine
{
    // A curated list of known dangerous namespaces and types used in .NET gadget chains
    private static readonly HashSet<string> DangerousTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Diagnostics.Process",
        "System.Configuration.Install.AssemblyInstaller",
        "System.Activities.Presentation.WorkflowDesigner",
        "System.Windows.ResourceDictionary",
        "System.Windows.Data.ObjectDataProvider",
        "System.Windows.Forms.BindingSource",
        "Microsoft.Exchange.Management.SystemManager.WinForm.ExchangeSettingsProvider",
        "System.IO.FileInfo",
        "System.IO.DirectoryInfo",
        "System.Reflection.Assembly",
        "System.Reflection.MethodInfo",
        "System.Type"
    };

    public DetectionResult Inspect(string? payload, string context = "Unknown")
    {
        if (string.IsNullOrEmpty(payload)) return DetectionResult.Safe();
        
        var typeName = payload;
        
        // Block exact dangerous types
        if (DangerousTypes.Contains(typeName))
        {
            return DetectionResult.Threat(
                threatType: "Insecure Deserialization", 
                description: "Attempt to deserialize known gadget chain type", 
                severity: ThreatSeverity.Critical, 
                confidence: 1.0, 
                matchedPattern: typeName);
        }

        return DetectionResult.Safe();
    }

    public DetectionResult Inspect(ReadOnlySpan<char> payload, string context = "Unknown")
    {
        if (payload.IsEmpty) return DetectionResult.Safe();

        // Delegate to string since HashSet lookup requires it in older .NET versions
        return Inspect(payload.ToString(), context);
    }
}
