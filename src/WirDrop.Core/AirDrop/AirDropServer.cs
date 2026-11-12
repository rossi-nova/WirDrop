using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using WirDrop.Core.Archive;
using WirDrop.Core.Http;
using WirDrop.Core.Net;
using WirDrop.Core.Security;

namespace WirDrop.Core.AirDrop;

public enum Visibility
{
    /// <summary>所有人可见。</summary>
    Everyone,

    /// <summary>仅联系人（Windows 上没有 Apple 身份，等价于不可见）。</summary>
    ContactsOnly,
}

/// <summary>一次 `/Ask` 的确认请求，交给界面层决定。</summary>
public sealed class IncomingAsk
{
    public required AskRequest Request { get; init; }

    public required IPEndPoint Remote { get; init; }

    /// <summary>由调用方完成；true 接受，false 拒绝。</summary>
    public TaskCompletionSource<bool> Decision { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>预览缩略图（JPEG 2000 或其它，来自对端）。</summary>
    public byte[]? Icon => Request.FileIcon;
}

public sealed class ReceiveCompletedEventArgs : EventArgs
{
    public required IReadOnlyList<string> Files { get; init; }

    public required string SenderName { get; init; }

    public required IPEndPoint Remote { get; init; }

    public bool Success { get; init; }
}

/// <summary>
/// AirDrop 接收端：在指定接口上监听 TLS 端口，响应 `/Discover` / `/Ask` / `/Upload`。
///
/// 端口约定：默认 8771（OpenDrop 与 Owly 都用它）；Apple 发送端按 SRV 记录里的端口连接，
/// 因此公告中写什么端口就监听什么端口即可。
/// </summary>
public sealed class AirDropServer : IAsyncDisposable
{
    public const int DefaultPort = 8771;

    private readonly NetworkInterfaceInfo? _iface;
    private readonly int _requestedPort;
    private TcpListener? _listener;
    private X509Certificate2? _certificate;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public AirDropServer(NetworkInterfaceInfo? iface, int port, string deviceName, string downloadDirectory)
    {
        _iface = iface;
        _requestedPort = port;
        DeviceName = deviceName;
        DownloadDirectory = downloadDirectory;
    }

    public string DeviceName { get; }

    public string DownloadDirectory { get; }

    public string? ServiceId { get; private set; }

    public ushort ActualPort { get; private set; }

    public string HostName { get; private set; } = Environment.MachineName.ToLowerInvariant();

    public string ComputerName => DeviceName;

    public Visibility Visibility { get; set; } = Visibility.Everyone;

    /// <summary>无人值守时是否自动接受 /Ask（默认拒绝；界面会订阅 <see cref="AskReceived"/>）。</summary>
    public bool AutoAccept { get; set; }

    public ReceiverFlags Flags { get; set; } = ReceiverFlags.Minimal;

    public X509Certificate2 Certificate => _certificate ?? throw new InvalidOperationException("服务端尚未启动");

    /// <summary>收到一个待确认的 `/Ask`；界面订阅后完成 <see cref="IncomingAsk.Decision"/>。</summary>
    public event EventHandler<IncomingAsk>? AskReceived;

    public event EventHandler<ReceiveCompletedEventArgs>? TransferCompleted;

    public event EventHandler<string>? Diagnostic;

    /// <summary>返回给 mDNS 公告的本机实例信息。</summary>
    public Mdns.AirdropServiceInstance LocalInstance => new()
    {
        InstanceName = $"{ServiceId}.{Mdns.MdnsBrowser.ServiceType}",
        HostName = HostName,
        Address = _iface?.Address ?? IPAddress.Loopback,
        Port = ActualPort,
        Flags = (int)Flags,
    };

    public void Start()
    {
        _cts = new CancellationTokenSource();
        ServiceId ??= Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
        var keyDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WirDrop", "identity");
        _certificate = AirDropTls.LoadOrCreateIdentity(keyDir, Environment.MachineName);

        var listener = ListenOn(_iface?.Address);
        ActualPort = (ushort)((IPEndPoint)listener.LocalEndpoint).Port;
        _listener = listener;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(listener, _cts.Token));
        HostName = SanitizeHost(Environment.MachineName);
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Stop();
    }

    private TcpListener ListenOn(IPAddress? bind)
    {
        if (bind is not null && bind.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var v6 = new TcpListener(bind, _requestedPort);
            try
            {
                v6.Server.DualMode = true;
                v6.Start();
                Diagnostic?.Invoke(this, $"监听 [{(IPEndPoint)v6.LocalEndpoint}]");
                return v6;
            }
            catch (SocketException ex)
            {
                v6.Stop();
                Diagnostic?.Invoke(this, $"监听 IPv6 失败：{ex.Message}，改用 IPv4");
            }
        }

        for (var offset = 0; offset < 20; offset++)
        {
            var listener = new TcpListener(IPAddress.Any, _requestedPort + offset);
            try
            {
                listener.Start();
                Diagnostic?.Invoke(this, $"监听 {listener.LocalEndpoint}");
                return listener;
            }
            catch (SocketException)
            {
                listener.Stop();
            }
        }

        throw new IOException("没有可用端口");
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                if (ct.IsCancellationRequested)
                {
                    return;
                }

                await Task.Delay(200, ct).ConfigureAwait(false);
                continue;
            }

            _ = Task.Run(() => HandleClientAsync(client, ct), CancellationToken.None);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        var remote = client.Client.RemoteEndPoint as IPEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(10));
            try
            {
                client.NoDelay = true;
                var stream = client.GetStream();
                using var tls = await AirDropTls.AcceptAsync(stream, _certificate!, timeout.Token).ConfigureAwait(false);
                try
                {
                    await ServeConnectionAsync(tls, remote, timeout.Token).ConfigureAwait(false);
                }
                finally
                {
                    // 先发 close_notify 再关闭底层 socket，避免最后一段响应被 RST 丢掉。
                    try
                    {
                        await tls.ShutdownAsync().ConfigureAwait(false);
                    }
                    catch (IOException)
                    {
                    }
                    catch (System.Security.Authentication.AuthenticationException)
                    {
                    }
                }
            }
            finally
            {
                client.Dispose();
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or SocketException)
        {
            Diagnostic?.Invoke(this, $"连接 {remote} 结束：{ex}");
        }
        catch (Exception ex)
        {
            // 兜底：任何协议或解包异常都不能让进程静默吞掉，必须记录并结束该连接。
            Diagnostic?.Invoke(this, $"连接 {remote} 异常：{ex}");
        }
    }

    private async Task ServeConnectionAsync(Stream stream, IPEndPoint remote, CancellationToken ct)
    {
        // HTTP-7：每条连接上 Discover / Ask / Upload 各一个槽位。
        var discoverUsed = false;
        AskRequest? acceptedAsk = null;
        var transferId = string.Empty;

        while (!ct.IsCancellationRequested)
        {
            HttpRequestHead? head;
            try
            {
                head = await AsyncFraming.ReadRequestHeadAsync(stream, ct).ConfigureAwait(false);
            }
            catch (HttpFramingException ex)
            {
                await TryWriteErrorAsync(stream, ex.StatusCode, ct).ConfigureAwait(false);
                return;
            }

            if (head is null)
            {
                return;
            }

            if (head.ExpectContinue)
            {
                await stream.WriteAsync("HTTP/1.1 100 Continue\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }

            Diagnostic?.Invoke(this, $"请求 {head.Target} kind={head.BodyKind} len={head.ContentLength} ct={head.Header("Content-Type")} tid={head.Header("TransferID")}");
            try
            {
                switch (head.Target)
                {
                    case "/Discover":
                        if (discoverUsed || acceptedAsk is not null)
                        {
                            await AsyncFraming.WriteResponseAsync(stream, 400, [], ct).ConfigureAwait(false);
                            return;
                        }

                        discoverUsed = true;
                        await HandleDiscoverAsync(stream, head, ct).ConfigureAwait(false);
                        break;

                    case "/Ask":
                    {
                        var body = await AsyncFraming.ReadBodyAsync(stream, head, ct).ConfigureAwait(false);
                        var ask = AskRequest.Parse(body);
                        // ASK-5：FileBomPath 必须在收到时就校验，早于弹窗与上传。
                        try { _ = new Archive.UploadExtractor(ask); }
                        catch (Archive.UploadException ex)
                        {
                            Diagnostic?.Invoke(this, $"/Ask 校验失败：{ex.Message}");
                            await AsyncFraming.WriteResponseAsync(stream, 400, [], ct).ConfigureAwait(false);
                            return;
                        }

                        discoverUsed = true;
                        var decision = await PromptAsync(ask, remote, ct).ConfigureAwait(false);
                        if (!decision)
                        {
                            await AsyncFraming.WriteResponseAsync(stream, 403, [], ct).ConfigureAwait(false);
                            return;
                        }

                        acceptedAsk = ask;
                        transferId = ask.TransferId ?? string.Empty;
                        var response = new AskResponse
                        {
                            ReceiverComputerName = ComputerName,
                            ReceiverModelName = "Windows",
                        };
                        await AsyncFraming.WriteResponseAsync(stream, 200, response.ToPlist(), ct).ConfigureAwait(false);
                        if (ask.IsLinkShare)
                        {
                            NotifyCompleted([], ask.SenderComputerName, remote, true);
                            return;
                        }

                        break;
                    }

                    case "/Upload":
                    {
                        if (acceptedAsk is null)
                        {
                            await TryWriteErrorAsync(stream, 400, ct).ConfigureAwait(false);
                            return;
                        }

                        var headerId = head.Header("TransferID");
                        if (acceptedAsk.TransferId is not null
                            && headerId is not null
                            && !string.Equals(headerId, acceptedAsk.TransferId, StringComparison.OrdinalIgnoreCase))
                        {
                            await TryWriteErrorAsync(stream, 400, ct).ConfigureAwait(false);
                            return;
                        }

                        var contentType = head.Header("Content-Type") ?? string.Empty;
                        if (!contentType.Equals("application/x-cpio", StringComparison.OrdinalIgnoreCase)
                            && !contentType.Equals("application/x-dvzip", StringComparison.OrdinalIgnoreCase))
                        {
                            await AsyncFraming.WriteResponseAsync(stream, 406, [], ct).ConfigureAwait(false);
                            return;
                        }

                        var files = await ReceiveUploadAsync(stream, head, acceptedAsk, contentType, ct).ConfigureAwait(false);
                        await AsyncFraming.WriteResponseAsync(stream, 200, [], ct).ConfigureAwait(false);
                        NotifyCompleted(files, acceptedAsk.SenderComputerName, remote, true);
                        return;
                    }

                    default:
                        await AsyncFraming.WriteResponseAsync(stream, 400, [], ct).ConfigureAwait(false);
                        return;
                }
            }
            catch (UploadException ex)
            {
                Diagnostic?.Invoke(this, $"拒绝上传：{ex}");
                if (acceptedAsk is not null)
                {
                    NotifyCompleted([], acceptedAsk.SenderComputerName, remote, false);
                }

                await AsyncFraming.WriteResponseAsync(stream, 400, [], ct).ConfigureAwait(false);
                return;
            }
            catch (HttpFramingException ex)
            {
                await TryWriteErrorAsync(stream, ex.StatusCode, ct).ConfigureAwait(false);
                return;
            }
            catch (FormatException ex)
            {
                Diagnostic?.Invoke(this, $"报文格式错误：{ex}");
                await AsyncFraming.WriteResponseAsync(stream, 400, [], ct).ConfigureAwait(false);
                return;
            }
        }
    }

    private async Task HandleDiscoverAsync(Stream stream, HttpRequestHead head, CancellationToken ct)
    {
        var body = await AsyncFraming.ReadBodyAsync(stream, head, ct).ConfigureAwait(false);
        _ = DiscoverRequest.Parse(body); // 允许空字典；无记录时也不做联系人校验。
        var visible = Visibility == Visibility.Everyone;
        var response = new DiscoverResponse
        {
            StatusCode = visible ? 100 : 401,
            ReceiverComputerName = visible ? ComputerName : null,
            ReceiverModelName = visible ? "Windows" : null,
            ReceiverMediaCapabilities = visible ? MediaCapabilities.Default : null,
        };
        await AsyncFraming.WriteResponseAsync(stream, 200, response.ToPlist(), ct).ConfigureAwait(false);
    }

    private async Task<bool> PromptAsync(AskRequest ask, IPEndPoint remote, CancellationToken ct)
    {
        var handler = AskReceived;
        if (handler is null)
        {
            // 没有界面订阅时按策略决定，便于无界面场景（测试/自动化）也能收文件。
            return AutoAccept;
        }

        var incoming = new IncomingAsk { Request = ask, Remote = remote };
        handler(this, incoming);
        await using var reg = ct.Register(() => incoming.Decision.TrySetResult(false));
        return await incoming.Decision.Task.ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<string>> ReceiveUploadAsync(Stream stream, HttpRequestHead head, AskRequest ask, string contentType, CancellationToken ct)
    {
        Directory.CreateDirectory(DownloadDirectory);
        var staging = Path.Combine(DownloadDirectory, $".wirdrop-staging-{Guid.NewGuid():N}");
        var extractor = new UploadExtractor(ask);
        try
        {
            // HttpFraming 目前一次性读取请求体；大文件由 CPS 调用 Drive/Host 实现分块流式，
            // 这里先读取到临时文件再解包。
            var bodyFile = Path.Combine(staging + ".body");
            await using (var body = new FileStream(bodyFile, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 20, FileOptions.Asynchronous))
            {
                await AsyncFraming.CopyBodyAsync(stream, head, body, ct).ConfigureAwait(false);
                body.Position = 0;
                var files = await extractor.ExtractAsync(body, contentType, staging, ct).ConfigureAwait(false);
                var final = new List<string>();
                foreach (var file in files)
                {
                    final.Add(MoveIntoPlace(file, DownloadDirectory));
                }

                return final;
            }
        }
        finally
        {
            TryDeleteDirectory(staging);
            TryDeleteFile(staging + ".body");
        }
    }

    private static string MoveIntoPlace(string stagedFile, string downloadDirectory)
    {
        Directory.CreateDirectory(downloadDirectory);
        var name = Path.GetFileName(stagedFile);
        var targetName = WindowsName.Sanitize(name);
        targetName = WindowsName.UniqueIn(downloadDirectory, targetName);
        var target = Path.Combine(downloadDirectory, targetName);
        File.Move(stagedFile, target);
        return target;
    }

    private void NotifyCompleted(IReadOnlyList<string> files, string sender, IPEndPoint remote, bool success)
    {
        try
        {
            TransferCompleted?.Invoke(this, new ReceiveCompletedEventArgs
            {
                Files = files,
                SenderName = sender,
                Remote = remote,
                Success = success,
            });
        }
        catch (Exception ex)
        {
            Diagnostic?.Invoke(this, $"完成事件处理失败：{ex.Message}");
        }
    }

    private static async Task TryWriteErrorAsync(Stream stream, int status, CancellationToken ct)
    {
        try
        {
            await AsyncFraming.WriteResponseAsync(stream, status, [], ct, ("Connection", "close")).ConfigureAwait(false);
        }
        catch (IOException)
        {
        }
    }

    private static string SanitizeHost(string host)
    {
        var s = new string(host.ToLowerInvariant().Where(c => char.IsAsciiLetterOrDigit(c) || c == '-').ToArray());
        return s.Length == 0 ? "wir" + Environment.ProcessId : s[..Math.Min(s.Length, 63)];
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        Stop();
        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _cts?.Dispose();
        _certificate?.Dispose();
    }
}