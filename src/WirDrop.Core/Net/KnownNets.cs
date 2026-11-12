using System.Net;
using System.Net.Sockets;

namespace WirDrop.Core.Net;

/// <summary>
/// 自解析的 IP 网段判断。不用 IPNetwork 的类型转换，避免 Linux 上 ".local" 解析成
/// link-local、Windows 上解析成 multicast 等跨平台歧义。
/// </summary>
public static class KnownNets
{
    public static bool IsLinkLocal(IPAddress a) =>
        a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6LinkLocal;

    public static bool IsLoopback(IPAddress a) =>
        a.AddressFamily == AddressFamily.InterNetworkV6
            ? IPAddress.IPv6Loopback.Equals(StripScope(a))
            : IPAddress.IsLoopback(a);

    /// <summary>IPv4 链路本地 169.254.0.0/16 或 IPv6 fe80::/10。</summary>
    public static bool IsAnyLinkLocal(IPAddress a) => a.AddressFamily switch
    {
        AddressFamily.InterNetworkV6 => a.IsIPv6LinkLocal,
        AddressFamily.InterNetwork => a.GetAddressBytes() is [169, 254, _, _],
        _ => false,
    };

    /// <summary>非回环、非组播、非未指定的单播地址。</summary>
    public static bool IsUsableUnicast(IPAddress a)
    {
        if (a.IsIPv6Multicast || IPAddress.IsLoopback(a))
        {
            return false;
        }

        if (a.AddressFamily == AddressFamily.InterNetworkV6 && IPAddress.IPv6Any.Equals(StripScope(a)))
        {
            return false;
        }

        if (a.AddressFamily == AddressFamily.InterNetwork && IPAddress.Any.Equals(a))
        {
            return false;
        }

        return true;
    }

    /// <summary>去掉 IPv6 的 scope id，只比较地址本身。</summary>
    public static IPAddress StripScope(IPAddress a)
    {
        if (a.AddressFamily != AddressFamily.InterNetworkV6 || a.ScopeId == 0)
        {
            return a;
        }

        return new IPAddress(a.GetAddressBytes());
    }

    /// <summary>在指定接口上的链路本地地址（或回环），用于 bind 源地址。</summary>
    public static IPAddress? FirstAddressOn(NetworkInterfaceInfo iface, bool linkLocalOnly = false)
    {
        var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
        foreach (var nic in nics)
        {
            if (!string.Equals(nic.Name, iface.Name, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(nic.Id, iface.Id, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                var ip = ua.Address;
                if (linkLocalOnly ? ip.IsIPv6LinkLocal : IsUsableUnicast(ip))
                {
                    return ip;
                }
            }
        }

        return null;
    }
}
