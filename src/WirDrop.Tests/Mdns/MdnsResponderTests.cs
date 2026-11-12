using System.Net;
using System.Net.Sockets;
using WirDrop.Core.Mdns;
using WirDrop.Core.Net;

namespace WirDrop.Tests.Mdns;

/// <summary>
/// 验证 mDNS 应答器按问题精确回答。Apple 的解析顺序是 PTR → SRV → A/AAAA，
/// 每一步单独发查询；只答 PTR 会让 iPhone 拿到名字却拿不到地址。
/// </summary>
public class MdnsResponderTests : IAsyncLifetime
{
    private MdnsBrowser? _browser;
    private UdpClient? _probe;
    private NetworkInterfaceInfo? _iface;
    private static int _port = 5353;

    public async Task InitializeAsync()
    {
        _iface = NetworkInterfaceInfo.Enumerate(includeLoopback: true).FirstOrDefault();
        if (_iface is null)
        {
            return;
        }

        _probe = new UdpClient(AddressFamily.InterNetwork);
        _probe.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        try
        {
            _probe.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsBrowser.Port));
            _probe.JoinMulticastGroup(MdnsBrowser.MulticastGroup);
        }
        catch (SocketException)
        {
            _probe?.Dispose();
            _probe = null;
            return;
        }

        _browser = new MdnsBrowser(_iface);
        await _browser.StartAsync(new AirdropServiceInstance
        {
            InstanceName = "abcdef123456." + MdnsBrowser.ServiceType,
            HostName = "wir-test.local",
            Address = _iface.Address.AddressFamily == AddressFamily.InterNetwork ? _iface.Address : IPAddress.Loopback,
            Port = 8771,
            Flags = 0x89,
        });
    }

    public async Task DisposeAsync()
    {
        if (_browser is not null)
        {
            await _browser.DisposeAsync();
        }

        _probe?.Dispose();
    }

    private static byte[] UnicastQuery(string name, DnsRecordType type)
    {
        var msg = DnsMessage.Query(name, type, unicast: true);
        return DnsCodec.Encode(msg);
    }

    [Fact]
    public async Task AnswersSrvQueryForInstanceName()
    {
        if (_browser is null || _probe is null)
        {
            return;
        }

        // 模拟 iPhone：问实例名的 SRV。
        var query = UnicastQuery("abcdef123456._airdrop._tcp.local", DnsRecordType.Srv);
        await _probe.SendAsync(query, new IPEndPoint(IPAddress.Loopback, MdnsBrowser.Port));
        var reply = await WaitForAsync(DnsRecordType.Srv);
        Assert.NotNull(reply);
        Assert.Equal("wir-test.local", reply!.Target?.TrimEnd('.'));
        Assert.Equal(8771, reply.Port);
    }

    [Fact]
    public async Task AnswersAddressQueryForHostName()
    {
        if (_browser is null || _probe is null || _iface is null)
        {
            return;
        }

        // 模拟 iPhone：问主机名的 A/AAAA。拿不到这一步，AirDrop 就连不上。
        var type = _iface.Address.AddressFamily == AddressFamily.InterNetwork ? DnsRecordType.A : DnsRecordType.Aaaa;
        var query = UnicastQuery("wir-test.local", type);
        await _probe.SendAsync(query, new IPEndPoint(IPAddress.Loopback, MdnsBrowser.Port));
        var reply = await WaitForAsync(type);
        Assert.NotNull(reply);
        Assert.NotNull(reply!.Address);
        Assert.Equal(_iface.Address, reply.Address);
    }

    [Fact]
    public async Task AnswersTxtQueryForFlags()
    {
        if (_browser is null || _probe is null)
        {
            return;
        }

        var query = UnicastQuery("abcdef123456._airdrop._tcp.local", DnsRecordType.Txt);
        await _probe.SendAsync(query, new IPEndPoint(IPAddress.Loopback, MdnsBrowser.Port));
        var reply = await WaitForAsync(DnsRecordType.Txt);
        Assert.NotNull(reply);
        Assert.Contains("flags=137", reply!.Texts!);
    }

    private async Task<DnsRecord?> WaitForAsync(DnsRecordType type)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!cts.IsCancellationRequested)
        {
            try
            {
                var result = await _probe!.ReceiveAsync(cts.Token);
                var msg = DnsCodec.Decode(result.Buffer);
                var hit = msg.Answers.Concat(msg.Additionals).FirstOrDefault(r => r.Type == type);
                if (hit is not null)
                {
                    return hit;
                }
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (SocketException)
            {
                return null;
            }
        }

        return null;
    }
}