using System.Net;
using System.Net.Sockets;

namespace Rasp.Core.Extensions;

internal static class IPAddressExtensions
{
    public static bool IsLinkLocal(this IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            // 169.254.0.0/16
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 169 && bytes[1] == 254;
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal;
        }

        return false;
    }

    public static bool IsUniqueLocal(this IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = ip.GetAddressBytes();
            // fc00::/7 (which means first byte is 1111 110x, i.e., 0xfc or 0xfd)
            return (bytes[0] & 0xfe) == 0xfc;
        }
        return false;
    }

    public static bool IsPrivateNetwork(this IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6SiteLocal || ip.IsUniqueLocal();
        }

        return false;
    }
}
