using System.IO;
using System.Collections.ObjectModel;
using Visibility = WirDrop.Core.AirDrop.Visibility;
using System.Net;
using System.Windows;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Mdns;
using WirDrop.Core.Net;

namespace WirDrop.Windows.Services;

/// <summary>界面展示用的一个对端。</summary>
public sealed class PeerViewModel : System.ComponentModel.INotifyPropertyChanged
{
    private string _status = "就绪";

    public required AirdropServiceInstance Instance { get; init; }

    public string ServiceId => Instance.ServiceId;

    public string DisplayName => Instance.InstanceName.Split('.')[0];

    public string Address => $"{Instance.Address}:{Instance.Port}";

    public string Flags => $"0x{Instance.Flags:x3}";

    public bool Discoverable { get; set; }

    public string Status
    {
        get => _status;
        set
        {
            _status = value;
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(Status)));
        }
    }

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
}

public sealed class LogEntry
{
    public DateTime Timestamp { get; } = DateTime.Now;

    public required string Message { get; init; }

    public override string ToString() => $"[{Timestamp:HH:mm:ss}] {Message}";
}

/// <summary>
/// 把 mDNS 发现、AirDrop 接收端与发送端串起来，供主窗口调用。
///
/// - <see cref="StartAsync"/> 选定网卡并启动接收端 + mDNS；
/// - <see cref="Peers"/> 是对端列表，界面直接绑定；
/// - <see cref="PendingAsk"/> 出现时界面弹出确认窗；
/// - <see cref="SendAsync"/> 发送文件/链接。
/// </summary>
public sealed class AirDropService : IAsyncDisposable
{
    private AirDropServer? _server;
    private MdnsBrowser? _browser;
    private NetworkInterfaceInfo? _iface;
    private readonly List<LogEntry> _log = [];

    public ObservableCollection<PeerViewModel> Peers { get; } = [];

    public ObservableCollection<LogEntry> Logs { get; } = [];

    public event EventHandler<IncomingAsk>? AskRequested;

    public event EventHandler<ReceiveCompletedEventArgs>? Received;

    public event EventHandler<int>? PeerCountChanged;

    public event EventHandler<(long Sent, long Total)>? SendProgress;

    public string DeviceName { get; set; } = Environment.MachineName;

    public string DownloadDirectory { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "WirDrop");

    public Visibility Visibility { get; set; } = Visibility.Everyone;

    public NetworkInterfaceInfo? Interface => _iface;

    /// <summary>正在监听的端口（启动后有效）。</summary>
    public int Port { get; private set; }

    public bool IsRunning => _server is not null;

    public IReadOnlyList<NetworkInterfaceInfo> Interfaces() => NetworkInterfaceInfo.Enumerate();

    public void AddLog(string message)
    {
        var entry = new LogEntry { Message = message };
        if (Application.Current is not null && !Application.Current.Dispatcher.CheckAccess())
        {
            Application.Current.Dispatcher.BeginInvoke(() => AppendLog(entry));
        }
        else
        {
            AppendLog(entry);
        }
    }

    private void AppendLog(LogEntry entry)
    {
        if (Application.Current is not null && !Application.Current.Dispatcher.CheckAccess())
        {
            Application.Current.Dispatcher.BeginInvoke(() => AppendLog(entry));
            return;
        }

        _log.Add(entry);
        Logs.Add(entry);
        while (Logs.Count > 500)
        {
            Logs.RemoveAt(0);
        }
    }

    private static void TraceStep(string m) => File.AppendAllText(Path.Combine(Path.GetTempPath(), "wirdrop-startup.log"), DateTime.Now.ToString("HH:mm:ss.fff") + " " + m + Environment.NewLine);

    public async Task StartAsync(NetworkInterfaceInfo? preferred = null, int port = AirDropServer.DefaultPort)
    {
        TraceStep("begin");
        await StopAsync();
        TraceStep("stopped old");
        Directory.CreateDirectory(DownloadDirectory);
        TraceStep("dir ok");
        _iface = preferred ?? NetworkInterfaceInfo.Enumerate().FirstOrDefault();
        if (_iface is null)
        {
            throw new InvalidOperationException("没有可用的网络接口");
        }

        var server = new AirDropServer(_iface, port, DeviceName, DownloadDirectory)
        {
            Visibility = Visibility,
        };
        server.Diagnostic += (_, m) => AddLog(m);
        server.AskReceived += (_, ask) => AskRequested?.Invoke(this, ask);
        server.TransferCompleted += (_, e) =>
        {
            Received?.Invoke(this, e);
            AddLog(e.Success
                ? $"已收到来自「{e.SenderName}」的 {e.Files.Count} 个文件"
                : $"来自「{e.SenderName}」的传输失败");
        };
        server.Start();
        TraceStep("server started " + server.ActualPort);
        Port = server.ActualPort;
        _server = server;

        var browser = new MdnsBrowser(_iface);
        browser.Diagnostic += (_, m) => AddLog(m);
        browser.InstanceFound += (_, inst) =>
        {
            Application.Current.Dispatcher.BeginInvoke(() => UpsertPeer(inst));
            _ = ProbePeerAsync(inst);
        };
        browser.InstanceLost += (_, name) =>
            Application.Current.Dispatcher.BeginInvoke(() => RemovePeer(name));
        TraceStep("mdns start begin");
        try { await browser.StartAsync(server.LocalInstance); } catch (Exception ex) { TraceStep("mdns EX " + ex); throw; }
        TraceStep("mdns started");
        _browser = browser;

        AddLog($"服务已启动：{DeviceName} · {_iface.DisplayName} · 端口 {server.ActualPort}");
    }

    private async Task ProbePeerAsync(AirdropServiceInstance inst)
    {
        var sender = new AirDropSender(_iface!, DeviceName, _server!.ServiceId ?? "000000000000");
        var response = await sender.DiscoverAsync(new IPEndPoint(inst.Address, inst.Port));
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            var peer = Peers.FirstOrDefault(p => p.ServiceId == inst.ServiceId);
            if (peer is not null)
            {
                peer.Discoverable = response is not null;
                peer.Status = response is not null ? "可见" : "不可见（需设为「所有人」）";
            }
        });
    }

    private void UpsertPeer(AirdropServiceInstance instance)
    {
        var existing = Peers.FirstOrDefault(p => p.ServiceId == instance.ServiceId);
        if (existing is not null)
        {
            return;
        }

        Peers.Add(new PeerViewModel { Instance = instance });
        AddLog($"发现设备 {instance.ServiceId} · {instance.Address}");
        PeerCountChanged?.Invoke(this, Peers.Count);
    }

    private void RemovePeer(string name)
    {
        var id = name.Split('.')[0];
        var peer = Peers.FirstOrDefault(p => p.ServiceId == id);
        if (peer is not null)
        {
            Peers.Remove(peer);
            AddLog($"设备 {id} 已离线");
            PeerCountChanged?.Invoke(this, Peers.Count);
        }
    }

    public async Task<SendResult> SendAsync(PeerViewModel peer, IReadOnlyList<string> paths, bool link = false)
    {
        if (_server is null || _iface is null)
        {
            return new SendResult(SendStatus.Failed, "服务未启动");
        }

        var sender = new AirDropSender(_iface, DeviceName, _server.ServiceId ?? "000000000000");
        sender.Progress += (sent, total) => SendProgress?.Invoke(this, (sent, total));
        var endpoint = new IPEndPoint(peer.Instance.Address, peer.Instance.Port);
        AddLog($"向 {peer.ServiceId} 发送 {paths.Count} 个项…");
        var result = await sender.SendAsync(endpoint, paths, link);
        AddLog(result.Status switch
        {
            SendStatus.Succeeded => "发送完成",
            SendStatus.Declined => "对方拒绝了传输",
            SendStatus.Unreachable => $"无法连接：{result.Message}",
            _ => $"发送失败：{result.Message}",
        });
        peer.Status = result.Status == SendStatus.Succeeded ? "已发送" : "失败";
        return result;
    }

    public async Task StopAsync()
    {
        if (_browser is not null)
        {
            await _browser.DisposeAsync();
            _browser = null;
        }

        if (_server is not null)
        {
            await _server.DisposeAsync();
            _server = null;
        }

        Peers.Clear();
        PeerCountChanged?.Invoke(this, 0);
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}