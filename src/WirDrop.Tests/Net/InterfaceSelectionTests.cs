using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using WirDrop.Core.Net;

namespace WirDrop.Tests.Net;

/// <summary>
/// 接口选择规则：无线优先、IPv4 优先、排除虚拟网卡；有线并非被排除，
/// 只要它是可用接口就会被选中（"有线或无线不限"）。
/// </summary>
public class InterfaceSelectionTests
{
    private static NetworkInterfaceInfo Make(string name, string ip, NetworkInterfaceType link, InterfaceKind kind = InterfaceKind.Ip) => new()
    {
        Id = name,
        Name = name,
        Kind = kind,
        Index = 0,
        LinkType = link,
        Address = IPAddress.Parse(ip),
        Addresses = [IPAddress.Parse(ip)],
    };

    [Fact]
    public void WirelessIsPreferredOverWired()
    {
        var wired = Make("以太网", "192.168.1.10", NetworkInterfaceType.Ethernet);
        var wireless = Make("WLAN", "192.168.1.11", NetworkInterfaceType.Wireless80211);
        var sorted = NetworkInterfaceInfo.SortByPreference([wired, wireless]);
        Assert.Equal("WLAN", sorted[0].Name);
    }

    [Fact]
    public void WirelessIsDetectedByLinkTypeNotJustName()
    {
        // 名字不含 Wi-Fi/WLAN，但系统报告为无线，也应被识别。
        var w = Make("Network Adapter 2", "10.0.0.5", NetworkInterfaceType.Wireless80211);
        Assert.True(w.IsWireless);
    }

    [Fact]
    public void WiredIsSelectedWhenItIsTheOnlyInterface()
    {
        var wired = Make("以太网", "192.168.30.60", NetworkInterfaceType.Ethernet);
        var sorted = NetworkInterfaceInfo.SortByPreference([wired]);
        Assert.Single(sorted);
        Assert.Equal("192.168.30.60", sorted[0].Address.ToString());
    }

    [Fact]
    public void Ipv4IsPreferredOverIpv6LinkLocal()
    {
        var v6 = Make("以太网", "fe80::1", NetworkInterfaceType.Ethernet);
        var v4 = Make("以太网", "192.168.0.5", NetworkInterfaceType.Ethernet);
        var sorted = NetworkInterfaceInfo.SortByPreference([v6, v4]);
        Assert.Equal(AddressFamily.InterNetwork, sorted[0].Address.AddressFamily);
    }

    [Fact]
    public void VirtualAdaptersRankBelowPhysical()
    {
        var virt = Make("vEthernet (Default Switch)", "172.27.128.1", NetworkInterfaceType.Ethernet);
        var phys = Make("以太网", "192.168.30.60", NetworkInterfaceType.Ethernet);
        var sorted = NetworkInterfaceInfo.SortByPreference([virt, phys]);
        Assert.Equal("以太网", sorted[0].Name);
    }

    [Fact]
    public void OnThisMachinePrimaryIsUsable()
    {
        // 真实环境下的冒烟检查：本机至少能选出一个可用接口。
        var primary = NetworkInterfaceInfo.Primary();
        Assert.NotNull(primary);
        Assert.False(primary!.Address.Equals(IPAddress.Any));
    }
}