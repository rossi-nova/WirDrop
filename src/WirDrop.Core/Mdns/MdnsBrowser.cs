using WirDrop.Core.Net;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace WirDrop.Core.Mdns;

/// <summary>一个被发现的 AirDrop 服务实例（某个对端的 <c>_airdrop._tcp</c> 记录）。</summary>
public sealed class AirdropServiceInstance
{
    public required string InstanceName { get; init; }

    /// <summary>服务 ID：12 位小写十六进制。</summary>
    public string ServiceId => InstanceName.Split('.')[0];

    public required string HostName { get; init; }

    public required IPAddress Address { get; init; }

    public required ushort Port { get; init; }

    public int Flags { get; init; }

    /// <summary>最近一次收到该记录的时刻。</summary>
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;

    public string Viewer { get; init; } = "everyone";

    public override string ToString() => $"{ServiceId} @ {Address}:{Port} flags=0x{Flags:x3}";

    public AirdropServiceInstance WithSeen() => new()
    {
        InstanceName = InstanceName,
        HostName = HostName,
        Address = Address,
        Port = Port,
        Flags = Flags,
        LastSeen = DateTimeOffset.UtcNow,
        Viewer = Viewer,
    };
}

/// <summary>
/// 基于 UDP 组播的 mDNS/DNS-SD 发现器，与 AirDrop 服务端（Mac/iPhone/iPad）互相可见。
///
/// 设计要点：
/// - 在指定网络接口上加入 224.0.0.251:5353 组播组，并绑定该接口地址；
/// - 发布本机的 <c>_airdrop._tcp</c> 实例（PTR/SRV/TXT/AAAA），定期重复公告（MDNS-7）；
/// - 浏览时对 <c>_airdrop._tcp.local</c> 发 PTR 查询，并解析应答中的 SRV/TXT/AAAA；
/// - 长期在线，自动响应他人的 PTR 查询。
/// </summary>
public sealed class MdnsBrowser : IAsyncDisposable
{
    public const string ServiceType = "_airdrop._tcp.local.";
    public static readonly IPAddress MulticastGroup = IPAddress.Parse("224.0.0.251");
    public const int Port = 5353;

    private readonly NetworkInterfaceInfo _iface;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, AirdropServiceInstance> _instances = new(StringComparer.OrdinalIgnoreCase);
    private UdpClient? _client;
    private Task? _loop;
    private Task? _announceLoop;
    private AirdropServiceInstance? _local;
    private DateTimeOffset _lastQuery = DateTimeOffset.MinValue;

    public MdnsBrowser(NetworkInterfaceInfo iface)
    {
        _iface = iface;
    }

    /// <summary>当前发现的对端（只读快照）。</summary>
    public IReadOnlyList<AirdropServiceInstance> Peers => _instances.Values.Where(i => i.LastSeen > DateTimeOffset.UtcNow.AddMinutes(-5)).ToList();

    public event EventHandler<AirdropServiceInstance>? InstanceFound;

    public event EventHandler<string>? InstanceLost;

    public event EventHandler<string>? Diagnostic;

    /// <summary>开始监听组播并启动查询循环。</summary>
    public async Task StartAsync(AirdropServiceInstance? local, CancellationToken ct = default)
    {
        _local = local;
        var endpoint = new IPEndPoint(IPAddress.Any, Port);
        var client = new UdpClient(AddressFamily.InterNetwork);
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
        client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
        try
        {
            client.Client.Bind(new IPEndPoint(_iface.Address.AddressFamily == AddressFamily.InterNetwork ? _iface.Address : IPAddress.Any, Port));
        }
        catch (SocketException)
        {
            client.Close();
            client = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        }

        try
        {
            client.JoinMulticastGroup(MulticastGroup, _iface.Address);
        }
        catch (SocketException ex)
        {
            Diagnostic?.Invoke(this, $"加入组播组失败（{_iface.Name}）：{ex.Message}");
        }

        _client = client;
        _loop = Task.Run(() => ReceiveLoopAsync(client, _cts.Token));
        _announceLoop = Task.Run(() => QueryLoopAsync(client, _cts.Token));
        await Task.CompletedTask;
    }

    /// <summary>立即发一次 PTR 查询。</summary>
    public void Query() => SendQuery(_client);

    private async Task ReceiveLoopAsync(UdpClient client, CancellationToken ct)
    {
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await client.ReceiveAsync(ct).ConfigureAwait(false);
                if (result.Buffer.Length > DnsCodec.MaxMessage)
                {
                    continue;
                }

                HandlePacket(result.Buffer, result.RemoteEndPoint);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException ex)
            {
                Diagnostic?.Invoke(this, $"mDNS 收包错误：{ex.Message}");
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
        }
    }

    private void HandlePacket(byte[] buffer, IPEndPoint remote)
    {
        DnsMessage message;
        try
        {
            message = DnsCodec.Decode(buffer);
        }
        catch (FormatException)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        // 1) 别人的查询：只要问的是 _airdrop._tcp，回答本机记录。
        if (!message.IsResponse)
        {
            if (_local is not null
                && message.Questions.Any(q => DnsCodec.NameEquals(q.Name, ServiceType) && (q.Type is DnsRecordType.Ptr or DnsRecordType.Any)))
            {
                RespondWithLocal();
            }

            return;
        }

        // 2) 应答：聚合 PTR/SRV/TXT/AAAA。
        var records = message.Answers.Concat(message.Additionals).ToList();
        var ptrTargets = records
            .Where(r => r.Type == DnsRecordType.Ptr && DnsCodec.NameEquals(r.Name, ServiceType) && r.Target is not null)
            .Select(r => r.Target!)
            .ToList();
        foreach (var instanceName in ptrTargets)
        {
            var srv = records.FirstOrDefault(r => r.Type == DnsRecordType.Srv && DnsCodec.NameEquals(r.Name, instanceName));
            var txt = records.FirstOrDefault(r => r.Type == DnsRecordType.Txt && DnsCodec.NameEquals(r.Name, instanceName));
            var existing = _instances.GetValueOrDefault(instanceName);
            var hostName = srv?.Target ?? existing?.HostName ?? "";
            var port = srv?.Port ?? existing?.Port ?? 0;
            var flags = ParseFlags(txt, existing?.Flags ?? 0);
            var address = records
                .Where(r => r.Type is DnsRecordType.Aaaa or DnsRecordType.A && hostName.Length > 0 && DnsCodec.NameEquals(r.Name, hostName))
                .Select(r => r.Address)
                .FirstOrDefault(a => a is not null)
                ?? existing?.Address
                ?? remote.Address;
            if (instanceName.Equals(_local?.InstanceName, StringComparison.OrdinalIgnoreCase))
            {
                continue; // 自己的回环
            }

            var instance = new AirdropServiceInstance
            {
                InstanceName = instanceName,
                HostName = hostName,
                Address = address,
                Port = port,
                Flags = flags,
            };
            var isNew = !_instances.ContainsKey(instanceName);
            _instances[instanceName] = instance;
            if (isNew || existing is null || existing.Address.Equals(instance.Address) is false || existing.Port != instance.Port)
            {
                InstanceFound?.Invoke(this, instance);
            }
        }

        // 3) 别人询问我们的记录（正常是查询，但有的实现会用应答形式）。忽略。
    }

    private static int ParseFlags(DnsRecord? txt, int fallback)
    {
        if (txt?.Texts is null)
        {
            return fallback;
        }

        foreach (var text in txt.Texts)
        {
            if (text.StartsWith("flags=", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(text[6..], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var flags))
            {
                return flags;
            }
        }

        return fallback;
    }

    private async Task QueryLoopAsync(UdpClient client, CancellationToken ct)
    {
        var announce = true;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (announce && _local is not null)
                {
                    RespondWithLocal();
                }
                else
                {
                    SendQuery(client);
                }

                announce = !announce;
                await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                await Task.Delay(1000, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private void SendQuery(UdpClient? client)
    {
        if (client is null)
        {
            return;
        }

        try
        {
            var message = DnsMessage.Query(ServiceType, DnsRecordType.Ptr);
            var bytes = DnsCodec.Encode(message);
            client.Send(bytes, bytes.Length, new IPEndPoint(MulticastGroup, Port));
            _lastQuery = DateTimeOffset.UtcNow;
        }
        catch (SocketException ex)
        {
            Diagnostic?.Invoke(this, $"mDNS 查询发送失败：{ex.Message}");
        }
    }

    /// <summary>公告本机服务：PTR + SRV + TXT + A/AAAA。</summary>
    public void RespondWithLocal()
    {
        var client = _client;
        if (client is null || _local is null)
        {
            return;
        }

        try
        {
            var instance = _local.InstanceName.EndsWith('.') ? _local.InstanceName : _local.InstanceName + ".";
            if (!instance.EndsWith(".local.", StringComparison.OrdinalIgnoreCase))
            {
                instance += "local.";
            }

            var host = _local.HostName.EndsWith('.') ? _local.HostName : _local.HostName + ".local.";
            var answers = new List<DnsRecord>
            {
                DnsRecord.Ptr(ServiceType, instance, 4500),
                DnsRecord.Srv(instance, _local.Port, host, 120),
                DnsRecord.Txt(instance, $"flags={_local.Flags}"),
            };
            if (_local.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                answers.Add(DnsRecord.A(host, _local.Address));
            }
            else
            {
                answers.Add(DnsRecord.Aaaa(host, _local.Address));
            }

            var message = new DnsMessage(0, true, [], answers, [], []);
            var bytes = DnsCodec.Encode(message);
            client.Send(bytes, bytes.Length, new IPEndPoint(MulticastGroup, Port));
        }
        catch (Exception ex) when (ex is SocketException or FormatException)
        {
            Diagnostic?.Invoke(this, $"mDNS 公告失败：{ex.Message}");
        }
    }

    /// <summary>清理超过 5 分钟未更新的对端。</summary>
    public void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);
        foreach (var (name, instance) in _instances)
        {
            if (instance.LastSeen < cutoff && _instances.TryRemove(name, out _))
            {
                InstanceLost?.Invoke(this, name);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        _client?.Close();
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        if (_announceLoop is not null)
        {
            try
            {
                await _announceLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _cts.Dispose();
    }
}
