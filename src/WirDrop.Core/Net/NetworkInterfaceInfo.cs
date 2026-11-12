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

    /// <summary>系统报告的真实链路类型</summary>
    public NetworkInterfaceType LinkType { get; init; } = NetworkInterfaceType.Unknown;

    /// <summary>是否无线链路（Wi-Fi）。AirDrop 在无线链路上体验最好，优先选择。</summary>
    public bool IsWireless => LinkType is NetworkInterfaceType.Wireless80211
        || Name.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)
        || Name.Contains("WLAN", StringComparison.OrdinalIgnoreCase)
        || Name.Contains("无线", StringComparison.Ordinal);

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
                LinkType = nic.NetworkInterfaceType,
                Address = chosen,
                Addresses = usable,
            });
        }

        return SortByPreference(result);
    }

    /// <summary>
    /// 排序规则（AirDrop 照此挑选默认接口）：
    /// 1) 无线优先（Wi-Fi 上体验最好，设备更多）；
    /// 2) 其次 IPv4（mDNS 走 IPv4 组播，链路本地 IPv6 到不了对端）；
    /// 3) 最后排除虚拟网卡（Hyper-V / VMware / VirtualBox）。
    /// 有线以太网在此规则下依然会被选中，只要它是唯一或最好的接口。
    /// </summary>
    public static List<NetworkInterfaceInfo> SortByPreference(IEnumerable<NetworkInterfaceInfo> interfaces) =>
        interfaces
            .OrderByDescending(i => i.IsWireless)
            .ThenByDescending(i => i.Address.AddressFamily == AddressFamily.InterNetwork)
            .ThenByDescending(i => !IsVirtual(i.Name))
            .ToList();

    private static bool IsVirtual(string name) =>
        name.Contains("vEthernet", StringComparison.OrdinalIgnoreCase)
        || name.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
        || name.Contains("VMware", StringComparison.OrdinalIgnoreCase)
        || name.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase);

    private static IPAddress SelectPreferred(IReadOnlyList<IPAddress> usable) =>
        usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && IsPrivate(a))
        ?? usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
        ?? usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6 && !a.IsIPv6LinkLocal)
        ?? usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6)
        ?? usable[0];

    private static bool IsPrivate(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254);
    }

    /// <summary>主用接口：优先首选，其次第一个。</summary>
    public static NetworkInterfaceInfo? Primary() => Enumerate().FirstOrDefault();
}
