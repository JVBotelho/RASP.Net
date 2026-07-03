using System;

namespace Rasp.Core.Enums;

[Flags]
public enum RaspSsrfIpBlock
{
    None = 0,

    /// <summary>
    /// 127.0.0.0/8 and ::1
    /// </summary>
    Loopback = 1 << 0,

    /// <summary>
    /// 0.0.0.0 and ::
    /// </summary>
    Unspecified = 1 << 1,

    /// <summary>
    /// 169.254.0.0/16 and fe80::/10 (AWS/Azure/GCP IMDS)
    /// </summary>
    LinkLocal = 1 << 2,

    /// <summary>
    /// 100.100.100.200
    /// </summary>
    AlibabaIMDS = 1 << 3,

    /// <summary>
    /// fc00::/7
    /// </summary>
    UniqueLocal = 1 << 4,

    /// <summary>
    /// RFC 1918 (10.x.x.x, 172.16.x.x, 192.168.x.x)
    /// </summary>
    PrivateNetwork = 1 << 5,

    /// <summary>
    /// All blocks except PrivateNetwork (which is usually controlled by an option flag)
    /// </summary>
    AllCritical = Loopback | Unspecified | LinkLocal | AlibabaIMDS | UniqueLocal
}
