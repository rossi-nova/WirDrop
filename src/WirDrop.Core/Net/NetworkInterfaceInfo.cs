using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace WirDrop.Core.Net;

public enum InterfaceKind
{
    /// <summary>Wi-Fi / 以太网 / USB 共享网络等普通 IP 接口。</summary>
    Ip,

    /// <summary>Apple 设备暴露的 AWDL 无线直连接口（awdl0）。Windows 上不存在，仅用于兼容保留。</summary>
    Awdl,
}

/// <summary>一块可收发 AirDrop 报文的本机网络接口。</summary>
public sealed class NetworkInterfaceInfo
{
    public required string Id { get; init; }

    /// <summary>接口名，例如 "Wi-Fi"、"以太网 2"、"awdl0"。</summary>
    public required string Name { get; init; }

    public InterfaceKind Kind { get; init; } = InterfaceKind.Ip;

    public required int Index { get; init; }

    /// <summary>选中的单播地址，用作 TLS 客户端源地址与 mDNS 组播落点。</summary>
    public required IPAddress Address { get; init; }

    /// <summary>同一接口上的全部单播地址。</summary>
    public required IReadOnlyList<IPAddress> Addresses { get; init; }

    public string DisplayName => Kind == InterfaceKind.Awdl ? $"{Name}（AWDL）" : Name;

    public override string ToString() => $"{DisplayName} · {KnownNets.StripScope(Address)}";

    /// <summary>枚举可供 AirDrop 使用的接口：IPv6 → IPv4 优先，链路本地 → 全局单播。</summary>
    public static List<NetworkInterfaceInfo> Enumerate(bool includeLoopback = false)
    {
        var result = new List<NetworkInterfaceInfo>();
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback && !includeLoopback)
            {
                continue;
            }

            IPInterfaceProperties props;
            int index;
            try
            {
                props = nic.GetIPProperties();
                index = props.GetIPv6Properties().Index;
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            var addresses = props.UnicastAddresses
                .Select(u => u.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetworkV6 || a.AddressFamily == AddressFamily.InterNetwork)
                .ToList();
            var usable = addresses.Where(KnownNets.IsUsableUnicast).ToList();
            if (usable.Count == 0)
            {
                continue;
            }

            var chosen = SelectPreferred(usable);
            result.Add(new NetworkInterfaceInfo
            {
                Id = nic.Id,
                Name = nic.Name,
                Index = index,
                Address = chosen,
                Addresses = usable,
            });
        }

        // Wi-Fi 优先（AirDrop 在无线链路上体验最好），再按 IPv6 链路本地优先。
        return result
            .OrderByDescending(i => i.Name.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)
                                    || i.Name.Contains("WLAN", StringComparison.OrdinalIgnoreCase)
                                    || i.Name.Contains("无线", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(i => i.Address.AddressFamily == AddressFamily.InterNetworkV6 && i.Address.IsIPv6LinkLocal)
            .ThenByDescending(i => i.Address.AddressFamily == AddressFamily.InterNetworkV6)
            .ToList();
    }

    private static IPAddress SelectPreferred(IReadOnlyList<IPAddress> usable) =>
        usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6LinkLocal)
        ?? usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6)
        ?? usable[0];

    /// <summary>主用接口：优先首选，其次第一个。</summary>
    public static NetworkInterfaceInfo? Primary() => Enumerate().FirstOrDefault();
}
