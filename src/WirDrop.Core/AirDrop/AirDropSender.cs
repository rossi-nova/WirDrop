using System.Net;
using System.Net.Sockets;
using WirDrop.Core.Archive;
using WirDrop.Core.Http;
using WirDrop.Core.Mdns;
using WirDrop.Core.Net;
using WirDrop.Core.Security;

namespace WirDrop.Core.AirDrop;

public enum SendStatus
{
    Succeeded,
    Declined,
    Failed,
    Unreachable,
}

public sealed record SendResult(SendStatus Status, string? Message = null);

/// <summary>
/// AirDrop 发送端：用 mDNS 找到对端后，按 §8.1 的流程逐个请求。
///
/// 连接与超时遵循 SPEC：连接 10s、/Discover 10s、/Ask 20s（长于接收端 15s）、上传写超时 30s、
/// 上传应答 60s。`/Ask` 与 `/Upload` 共用一条 TLS 连接（HTTP-1）。
/// </summary>
public sealed class AirDropSender
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan DiscoverTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AskTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan UploadWriteTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan UploadResponseTimeout = TimeSpan.FromSeconds(60);

    private readonly NetworkInterfaceInfo _iface;
    private readonly string _senderName;
    private readonly string _senderId;
    private readonly string _model;

    public AirDropSender(NetworkInterfaceInfo iface, string senderName, string senderId, string model = "Windows")
    {
        _iface = iface;
        _senderName = senderName;
        _senderId = senderId;
        _model = model;
    }

    public event Action<long, long>? Progress;

    /// <summary>探测对端是否对我们可见（DISC-1）。</summary>
    public async Task<DiscoverResponse?> DiscoverAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        try
        {
            using var client = await ConnectTcpAsync(endpoint, ct).ConfigureAwait(false);
            var tls = await AirDropTls.ConnectAsync(client.GetStream(), null, ct).ConfigureAwait(false);
            await using (tls)
            {
                var request = new DiscoverRequest
                {
                    SenderComputerName = _senderName,
                    SenderModelName = _model,
                    SenderId = _senderId,
                };
                await WritePostAsync(tls, "/Discover", request.ToPlist(), ct, DiscoverTimeout).ConfigureAwait(false);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(DiscoverTimeout);
                var head = await HttpResponseParser.ReadAsync(tls, timeout.Token).ConfigureAwait(false)
                           ?? throw new IOException("对端关闭了连接");
                if (head.StatusCode != 200)
                {
                    return null;
                }

                var body = await HttpResponseParser.ReadBodyAsync(tls, head, timeout.Token).ConfigureAwait(false);
                var response = DiscoverResponse.Parse(body);
                return response.Visible ? response : null;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or FormatException or OperationCanceledException or
                                       System.Security.Authentication.AuthenticationException)
        {
            return null;
        }
    }

    /// <summary>发送文件或链接。</summary>
    public async Task<SendResult> SendAsync(
        IPEndPoint endpoint,
        IReadOnlyList<string> paths,
        bool isLinkShare = false,
        CancellationToken ct = default)
    {
        UploadBuilder.PreparedUpload? prepared = null;
        try
        {
            TcpClient client;
            try
            {
                client = await ConnectTcpAsync(endpoint, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                return new SendResult(SendStatus.Unreachable, ex.Message);
            }

            using (client)
            {
                var tls = await AirDropTls.ConnectAsync(client.GetStream(), null, ct).ConfigureAwait(false);
                await using (tls)
                {
                    if (isLinkShare)
                    {
                        prepared = UploadBuilder.PrepareLinks(paths);
                    }
                    else
                    {
                        prepared = await UploadBuilder.PrepareFilesAsync(paths, dvzip: false, ct).ConfigureAwait(false);
                    }

                    var transferId = Guid.NewGuid().ToString("D").ToUpperInvariant();
                    var ask = new AskRequest
                    {
                        TransferId = transferId,
                        SenderComputerName = _senderName,
                        SenderModelName = _model,
                        SenderId = _senderId,
                        Files = prepared.Files,
                        Items = isLinkShare ? paths : [],
                    };

                    // /Ask 与 /Upload 必须共用一条连接（HTTP-1）。
                    await WritePostAsync(tls, "/Ask", ask.ToPlist(), ct, AskTimeout).ConfigureAwait(false);
                    AskResponse askResponse;
                    using (var askTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                    {
                        askTimeoutCts.CancelAfter(AskTimeout);
                        try
                        {
                            var head = await HttpResponseParser.ReadAsync(tls, askTimeoutCts.Token).ConfigureAwait(false);
                            if (head is null)
                            {
                                return new SendResult(SendStatus.Declined, "对端关闭连接");
                            }

                            if (head.StatusCode != 200)
                            {
                                return new SendResult(SendStatus.Declined);
                            }

                            var body = await HttpResponseParser.ReadBodyAsync(tls, head, askTimeoutCts.Token).ConfigureAwait(false);
                            askResponse = TryParseAsk(body) ?? new AskResponse { ReceiverComputerName = "", ReceiverModelName = "" };
                        }
                        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                        {
                            return new SendResult(SendStatus.Declined, "等待对端确认超时");
                        }
                    }

                    _ = askResponse;
                    if (isLinkShare || prepared.Length == 0)
                    {
                        return new SendResult(SendStatus.Succeeded);
                    }

                    return await UploadAsync(tls, prepared, transferId, ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new SendResult(SendStatus.Failed, "传输超时");
        }
        catch (Exception ex) when (ex is IOException or SocketException or FormatException or UploadException or InvalidOperationException or ObjectDisposedException)
        {
            return new SendResult(SendStatus.Failed, ex.ToString());
        }
        catch (Exception ex)
        {
            return new SendResult(SendStatus.Failed, "unexpected: " + ex);
        }
        finally
        {
            if (prepared is not null)
            {
                await prepared.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<SendResult> UploadAsync(Stream tls, UploadBuilder.PreparedUpload prepared, string transferId, CancellationToken ct)
    {
        var head = $"POST /Upload HTTP/1.1\r\nUser-Agent: AirDrop/1.0\r\nTransferID: {transferId}\r\nTotalBytes: {prepared.Files.Sum(f => f.FileSize)}\r\nContent-Type: application/x-cpio\r\nConnection: keep-alive\r\nContent-Length: {prepared.Length}\r\n\r\n";
        await tls.WriteAsync(System.Text.Encoding.ASCII.GetBytes(head), ct).ConfigureAwait(false);
        await tls.FlushAsync(ct).ConfigureAwait(false);

        await using var file = new FileStream(prepared.Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.Asynchronous);
        var buffer = new byte[1 << 20];
        long sent = 0;
        while (true)
        {
            var n = await file.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }

            using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            writeCts.CancelAfter(UploadWriteTimeout);
            try
            {
                await tls.WriteAsync(buffer.AsMemory(0, n), writeCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new SendResult(SendStatus.Failed, "对端停止读取");
            }

            sent += n;
            Progress?.Invoke(sent, prepared.Length);
        }

        await tls.FlushAsync(ct).ConfigureAwait(false);
        using var responseCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        responseCts.CancelAfter(UploadResponseTimeout);
        try
        {
            var headRead = await HttpResponseParser.ReadAsync(tls, responseCts.Token).ConfigureAwait(false);
            if (headRead is null)
            {
                return new SendResult(SendStatus.Failed, "对端未返回结果");
            }

            return headRead.StatusCode == 200 ? new SendResult(SendStatus.Succeeded) : new SendResult(SendStatus.Failed, $"对端返回 {headRead.StatusCode}");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new SendResult(SendStatus.Failed, "等待上传结果超时");
        }
    }

    private static bool IsSuccess(string statusLine) =>
        statusLine.StartsWith("200", StringComparison.Ordinal);

    private static AskResponse? TryParseAsk(byte[] body)
    {
        try
        {
            var dict = Core.Plist.BinaryPlist.Parse(body) as Dictionary<string, object?>;
            if (dict is null)
            {
                return null;
            }

            return new AskResponse
            {
                ReceiverComputerName = dict.GetValueOrDefault("ReceiverComputerName") as string ?? "",
                ReceiverModelName = dict.GetValueOrDefault("ReceiverModelName") as string ?? "",
            };
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static async Task WritePostAsync(Stream tls, string path, byte[] body, CancellationToken ct, TimeSpan timeout)
    {
        var head = $"POST {path} HTTP/1.1\r\nUser-Agent: AirDrop/1.0\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nContent-Length: {body.Length}\r\n\r\n";
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        await tls.WriteAsync(System.Text.Encoding.ASCII.GetBytes(head), cts.Token).ConfigureAwait(false);
        await tls.WriteAsync(body, cts.Token).ConfigureAwait(false);
        await tls.FlushAsync(cts.Token).ConfigureAwait(false);
    }

    private async Task<TcpClient> ConnectTcpAsync(IPEndPoint endpoint, CancellationToken ct)
    {
        var client = new TcpClient(endpoint.AddressFamily);
        try
        {
            // 绑定源地址，保证请求从所选网卡发出（多网卡/有线+无线并存时尤其重要）。
            if (endpoint.AddressFamily == AddressFamily.InterNetwork && _iface.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                client.Client.Bind(new IPEndPoint(_iface.Address, 0));
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(ConnectTimeout);
            await client.ConnectAsync(endpoint, cts.Token).ConfigureAwait(false);
            client.NoDelay = true;
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }
}