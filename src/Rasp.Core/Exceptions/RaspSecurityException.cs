using System;

namespace Rasp.Core.Exceptions;

/// <summary>
/// Exception thrown when RASP detects and blocks a security threat.
/// Does NOT derive from DbException to avoid being caught by transient fault handling strategies (retries).
/// </summary>
public sealed class RaspSecurityException : Exception
{
    public string ThreatType { get; } = string.Empty;
    public string Description { get; } = string.Empty;

    public RaspSecurityException()
        : base("RASP Security Block")
    {
    }

    public RaspSecurityException(string message)
        : base(message)
    {
    }

    public RaspSecurityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public RaspSecurityException(string threatType, string description)
        : base($"RASP Security Block [{threatType}]: {description}")
    {
        ThreatType = threatType;
        Description = description;
    }
}
