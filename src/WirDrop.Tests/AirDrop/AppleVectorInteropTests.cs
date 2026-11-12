using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.Json;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Net;
using WirDrop.Core.Plist;
using WirDrop.Tests.Support;

namespace WirDrop.Tests.AirDrop;

/// <summary>
/// 用 OpenDrop/Owly 仓库中"按 Apple sharingd 行为重建"的完整请求字节，
/// 原样喂给本机接收端，逐字段核对解析结果。
///
/// 这些向量覆盖了 iPhone 实际发出的线格式：chunked / Content-Length 两种分帧、
/// 当前形态与 legacy 形态的 /Ask、DVZip 与 gzip 的 /Upload。
/// </summary>
public class AppleVectorInteropTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "wirdrop-apple-" + Guid.NewGuid().ToString("N"));
    private static int _port = 19700;

    public AppleVectorInteropTests() => Directory.CreateDirectory(_root);

    private static NetworkInterfaceInfo Loopback() => new()
    {
        Id = "vec-loopback",
        Name = "vec-loopback",
        Index = 0,
        Address = IPAddress.Loopback,
        Addresses = [IPAddress.Loopback],
    };

    private async Task<(AirDropServer Server, SslStream Tls, TcpClient Tcp)> ConnectAsync()
    {
        var server = new AirDropServer(Loopback(), Interlocked.Increment(ref _port), "Vector Receiver", Path.Combine(_root, "dl"))
        {
            AutoAccept = true,
        };
        server.Start();
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, server.ActualPort);
        var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync("airdrop.local");
        return (server, tls, tcp);
    }

    /// <summary>把一条已编码的完整请求字节发给接收端，返回状态码。</summary>
    private static async Task<int> SendRawAsync(Stream s, byte[] request)
    {
        await s.WriteAsync(request);
        await s.FlushAsync();
        var head = await WirDrop.Core.Http.HttpResponseParser.ReadAsync(s)
                   ?? throw new InvalidOperationException("接收端未返回响应");
        await WirDrop.Core.Http.HttpResponseParser.ReadBodyAsync(s, head);
        return head.StatusCode;
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task DiscoverVectorsAreAccepted(int index)
    {
        var v = Vectors.Of("discover")[index];
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var request = Vectors.B64(v, "request_b64");
            Assert.Equal(200, await SendRawAsync(tls, request));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Theory]
    [InlineData("ios18-hello")]
    [InlineData("ios18-three-files")]
    [InlineData("legacy-hello")]
    [InlineData("ios18-photo")]
    public async Task AskVectorsParseExactlyAsAppleDescribes(string name)
    {
        var v = Vectors.Of("ask").First(x => Vectors.Name(x) == name);
        var expected = v.GetProperty("expect");

        // 1) 先直接用解析器核对报文内容（不经网络，定位更快）。
        var body = Vectors.B64(v, "body_b64");
        var ask = AskRequest.Parse(body);
        Assert.Equal(expected.GetProperty("transfer_id").GetString(), ask.TransferId);
        var expectedFiles = expected.GetProperty("files").EnumerateArray().ToList();
        Assert.Equal(expectedFiles.Count, ask.Files.Count);
        for (var i = 0; i < expectedFiles.Count; i++)
        {
            var e = expectedFiles[i];
            Assert.Equal(e.GetProperty("name").GetString(), ask.Files[i].FileName);
            Assert.Equal(e.GetProperty("bom_path").GetString(), ask.Files[i].FileBomPath);
            Assert.Equal(e.GetProperty("type").GetString(), ask.Files[i].FileType);
            if (e.GetProperty("size").ValueKind == JsonValueKind.Number)
            {
                Assert.Equal(e.GetProperty("size").GetInt64(), ask.Files[i].FileSize);
            }
        }

        // 2) 再走完整网络链路，确认请求能被接受。
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            Assert.Equal(200, await SendRawAsync(tls, Vectors.B64(v, "request_b64")));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task UploadVectorsExtractExactBytes(int index)
    {
        var v = Vectors.Of("upload")[index];
        var uploadRequest = Vectors.B64(v, "request_b64");
        var expectedFiles = v.GetProperty("expect").GetProperty("files").EnumerateArray().ToList();

        // 上传向量引用一条 /Ask（after_ask），用它的请求头 + body 建立白名单。
        var askName = v.TryGetProperty("after_ask", out var afterAsk) ? afterAsk.GetString() : null;
        var askVector = askName is not null
            ? Vectors.Of("ask").First(x => Vectors.Name(x) == askName)
            : throw new InvalidOperationException($"未知的 after_ask：{askName}");
        var askRequest = Vectors.B64(askVector, "request_b64");
        var askBody = Vectors.B64(askVector, "body_b64");
        var ask = AskRequest.Parse(askBody);

        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            // 同一连接：先 /Discover（可选跳过），再 /Ask，再 /Upload。
            var (_, askTcp, askTls) = (server, tcp, tls);
            _ = askTcp;
            Assert.Equal(200, await SendRawAsync(askTls, askRequest));
            Assert.Equal(200, await SendRawAsync(askTls, uploadRequest));
            await Task.Delay(400);

            foreach (var e in expectedFiles)
            {
                var path = e.GetProperty("path").GetString()!;
                var expected = Vectors.B64(e, "data_b64");
                var name = path.Split('/').Last();
                var hits = Directory.GetFiles(Path.Combine(_root, "dl"), name + "*");
                Assert.True(hits.Length > 0, $"缺少文件 {name}");
                Assert.Equal(expected, await File.ReadAllBytesAsync(hits[0]));
            }

            Assert.Equal(ask.Files.Count, expectedFiles.Count);
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}