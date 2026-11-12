using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Http;
using WirDrop.Core.Net;
using WirDrop.Core.Plist;

namespace WirDrop.Tests.AirDrop;

/// <summary>
/// 用"Apple 发送端形态"的原始线上报文访问本机接收端，覆盖真机最容易踩到的路径：
/// 单连接上依次 /Discover、/Ask、/Upload（HTTP-1）、Expect: 100-continue、
/// DVZip stored 块、gzip+odc、以及拒绝后的连接行为。
/// </summary>
public class WireProtocolTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "wirdrop-wire-" + Guid.NewGuid().ToString("N"));

    public WireProtocolTests() => Directory.CreateDirectory(_root);

    private static NetworkInterfaceInfo Loopback() => new()
    {
        Id = "test-loopback",
        Name = "test-loopback",
        Index = 0,
        Address = IPAddress.Loopback,
        Addresses = [IPAddress.Loopback],
    };

    private static int _nextPort = 19500;

    private async Task<(AirDropServer Server, SslStream Tls, TcpClient Tcp)> ConnectAsync(Action<AirDropServer>? configure = null)
    {
        var server = new AirDropServer(Loopback(), Interlocked.Increment(ref _nextPort), "Wire Receiver", Path.Combine(_root, "dl"))
        {
            AutoAccept = true,
        };
        configure?.Invoke(server);
        server.Start();
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, server.ActualPort);
        var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("airdrop.local");
        return (server, ssl, tcp);
    }

    private static async Task<HttpResponseHead> PostAsync(Stream s, string path, byte[] body, string contentType = "application/octet-stream", Dictionary<string, string>? extra = null, bool chunked = false, bool expectContinue = false)
    {
        var sb = new StringBuilder();
        sb.Append("POST ").Append(path).Append(" HTTP/1.1\r\n");
        sb.Append("User-Agent: AirDrop/1.0\r\n");
        sb.Append("Content-Type: ").Append(contentType).Append("\r\n");
        sb.Append("Connection: keep-alive\r\n");
        if (expectContinue)
        {
            sb.Append("Expect: 100-continue\r\n");
        }

        if (extra is not null)
        {
            foreach (var (k, v) in extra)
            {
                sb.Append(k).Append(": ").Append(v).Append("\r\n");
            }
        }

        if (chunked)
        {
            sb.Append("Transfer-Encoding: chunked\r\n\r\n");
        }
        else
        {
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n\r\n");
        }

        await s.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()));

        if (expectContinue)
        {
            var interim = await HttpResponseParser.ReadAsync(s);
            if (interim?.StatusCode != 100)
            {
                throw new InvalidOperationException($"期望 100 Continue，实际 {interim?.StatusCode}");
            }
        }

        if (chunked)
        {
            await s.WriteAsync(Encoding.ASCII.GetBytes($"{body.Length:x}\r\n"));
            await s.WriteAsync(body);
            await s.WriteAsync("\r\n0\r\n\r\n"u8.ToArray());
        }
        else
        {
            await s.WriteAsync(body);
        }

        await s.FlushAsync();
        var head = await HttpResponseParser.ReadAsync(s) ?? throw new InvalidOperationException("对端关闭");
        await HttpResponseParser.ReadBodyAsync(s, head);
        return head;
    }

    private static byte[] Odc(string name, int mode, long size, byte[]? data = null)
    {
        var nm = Encoding.UTF8.GetBytes(name + "\0");
        var h = "070707" + "000000" + "000001" + Convert.ToString(mode, 8).PadLeft(6, '0') + "000000" + "000000" + "000001" + "000000"
                + Convert.ToString(1700000000L, 8).PadLeft(11, '0')
                + Convert.ToString(nm.Length, 8).PadLeft(6, '0')
                + Convert.ToString(size, 8).PadLeft(11, '0');
        return [.. Encoding.ASCII.GetBytes(h), .. nm, .. data ?? []];
    }

    private static byte[] OdcArchive(params (string Name, int Mode, byte[] Data)[] entries)
    {
        using var ms = new MemoryStream();
        ms.Write(Odc(".", 16877, 0));
        foreach (var e in entries)
        {
            ms.Write(Odc(e.Name, e.Mode, e.Data.Length, e.Data));
        }

        ms.Write(Odc("TRAILER!!!", 0, 0));
        return ms.ToArray();
    }

    private static byte[] DvZipStored(byte[] raw)
    {
        using var ms = new MemoryStream();
        Span<byte> h = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(h, 0x80000000u | (uint)raw.Length);
        ms.Write(h);
        ms.Write(raw);
        return ms.ToArray();
    }

    private static byte[] AskPlist(string fileName, long size, string? transferId = null, bool legacy = false)
    {
        var dict = new Dictionary<string, object?>
        {
            ["SenderComputerName"] = "iPhone",
            ["BundleID"] = "com.apple.mobileslideshow",
            ["SenderModelName"] = "iPhone15,2",
            ["SenderID"] = "eeeeeeeeeeee",
            ["ConvertMediaFormats"] = false,
            ["Files"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["FileName"] = fileName,
                    ["FileType"] = "public.jpeg",
                    ["FileBomPath"] = "./" + fileName,
                    ["FileIsDirectory"] = false,
                    ["FileSize"] = size,
                    ["ShouldConvertMediaFormats"] = false,
                },
            },
            ["Items"] = new List<object?>(),
        };
        if (!legacy)
        {
            dict["TransferID"] = new Dictionary<string, object?> { ["id"] = transferId ?? Guid.NewGuid().ToString("D").ToUpperInvariant() };
            dict["TransferType"] = new Dictionary<string, object?> { ["files"] = new Dictionary<string, object?>() };
        }

        return BinaryPlist.Serialize(dict);
    }

    [Fact]
    public async Task SingleConnectionDiscoverAskUploadWithExpectContinue()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var payload = Encoding.UTF8.GetBytes("JPEG bytes here \u0001\u0002");
            var discover = await PostAsync(tls, "/Discover", BinaryPlist.Serialize(new Dictionary<string, object?>()));
            Assert.Equal(200, discover.StatusCode);

            var askBody = AskPlist("IMG_0001.JPG", payload.Length);
            var ask = await PostAsync(tls, "/Ask", askBody, expectContinue: true);
            Assert.Equal(200, ask.StatusCode);

            var archive = DvZipStored(OdcArchive(("./IMG_0001.JPG", 33188, payload)));
            var upload = await PostAsync(tls, "/Upload", archive, "application/x-dvzip", chunked: true);
            Assert.Equal(200, upload.StatusCode);

            await Task.Delay(300);
            var files = Directory.GetFiles(Path.Combine(_root, "dl"));
            Assert.Single(files);
            Assert.EndsWith("IMG_0001.JPG", files[0], StringComparison.Ordinal);
            Assert.Equal(payload, await File.ReadAllBytesAsync(files[0]));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task GzipCpioUploadIsAccepted()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var payload = Encoding.UTF8.GetBytes("gzip payload");
            var ask = await PostAsync(tls, "/Ask", AskPlist("note.txt", payload.Length));
            Assert.Equal(200, ask.StatusCode);

            using var gz = new MemoryStream();
            using (var gzip = new System.IO.Compression.GZipStream(gz, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
            {
                var archive = OdcArchive(("./note.txt", 33188, payload));
                gzip.Write(archive);
            }

            var upload = await PostAsync(tls, "/Upload", gz.ToArray(), "application/x-cpio");
            Assert.Equal(200, upload.StatusCode);
            await Task.Delay(300);
            var received = Directory.GetFiles(Path.Combine(_root, "dl")).Single(f => f.EndsWith("note.txt", StringComparison.Ordinal));
            Assert.Equal(payload, await File.ReadAllBytesAsync(received));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task UploadWithoutAcceptedAskIsRejected()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var archive = DvZipStored(OdcArchive(("./x.jpg", 33188, "abc"u8.ToArray())));
            var upload = await PostAsync(tls, "/Upload", archive, "application/x-dvzip");
            Assert.Equal(400, upload.StatusCode);
            await Task.Delay(200);
            Assert.False(Directory.Exists(Path.Combine(_root, "dl")) && Directory.GetFiles(Path.Combine(_root, "dl")).Length > 0);
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task UnlistedArchiveEntryIsRejected()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var ask = await PostAsync(tls, "/Ask", AskPlist("wanted.jpg", 3));
            Assert.Equal(200, ask.StatusCode);

            // 归档里放一个 /Ask 没有列出的条目，必须整体拒绝。
            var archive = DvZipStored(OdcArchive(("./evil.sh", 33188, "rm -rf /"u8.ToArray())));
            var upload = await PostAsync(tls, "/Upload", archive, "application/x-dvzip");
            Assert.NotEqual(200, upload.StatusCode);
            await Task.Delay(300);
            var dl = Path.Combine(_root, "dl");
            var leftover = Directory.Exists(dl) ? Directory.GetFiles(dl) : [];
            Assert.DoesNotContain(leftover, f => f.EndsWith("evil.sh", StringComparison.Ordinal));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PathTraversalEntryIsRejected()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            // /Ask 自身就带 ../，必须在解析阶段被拒绝。
            var dict = new Dictionary<string, object?>
            {
                ["SenderComputerName"] = "attacker",
                ["SenderID"] = "aaaaaaaaaaaa",
                ["SenderModelName"] = "x",
                ["BundleID"] = "x",
                ["ConvertMediaFormats"] = false,
                ["Files"] = new List<object?>
                {
                    new Dictionary<string, object?>
                    {
                        ["FileName"] = "passwd",
                        ["FileType"] = "public.data",
                        ["FileBomPath"] = "./../../passwd",
                        ["FileIsDirectory"] = false,
                        ["FileSize"] = 1L,
                        ["ShouldConvertMediaFormats"] = false,
                    },
                },
            };
            var ask = await PostAsync(tls, "/Ask", BinaryPlist.Serialize(dict));
            Assert.True(ask.StatusCode is 400 or 403, $"实际 {ask.StatusCode}");
            Assert.False(File.Exists(Path.Combine(_root, "passwd")));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task DuplicateNameGetsUniqueSuffix()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var dl = Path.Combine(_root, "dl");
            Directory.CreateDirectory(dl);
            await File.WriteAllTextAsync(Path.Combine(dl, "IMG_0002.JPG"), "existing");

            var payload = "new content"u8.ToArray();
            await PostAsync(tls, "/Ask", AskPlist("IMG_0002.JPG", payload.Length));
            await PostAsync(tls, "/Upload", DvZipStored(OdcArchive(("./IMG_0002.JPG", 33188, payload))), "application/x-dvzip");
            await Task.Delay(400);

            var files = Directory.GetFiles(dl).Select(Path.GetFileName).ToList();
            Assert.Contains("IMG_0002.JPG", files);
            Assert.Contains(files, f => f!.StartsWith("IMG_0002 (1)", StringComparison.Ordinal));
            Assert.Equal("existing", await File.ReadAllTextAsync(Path.Combine(dl, "IMG_0002.JPG")));
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task LegacyAskWithoutTransferIdIsAccepted()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var payload = "legacy"u8.ToArray();
            var ask = await PostAsync(tls, "/Ask", AskPlist("old.jpg", payload.Length, legacy: true));
            Assert.Equal(200, ask.StatusCode);
            var upload = await PostAsync(tls, "/Upload", DvZipStored(OdcArchive(("./old.jpg", 33188, payload))), "application/x-dvzip");
            Assert.Equal(200, upload.StatusCode);
        }
        finally
        {
            await tls.DisposeAsync();
            tcp.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task SecondDiscoverOnSameConnectionIsRejected()
    {
        var (server, tls, tcp) = await ConnectAsync();
        try
        {
            var first = await PostAsync(tls, "/Discover", BinaryPlist.Serialize(new Dictionary<string, object?>()));
            Assert.Equal(200, first.StatusCode);
            var second = await PostAsync(tls, "/Discover", BinaryPlist.Serialize(new Dictionary<string, object?>()));
            Assert.Equal(400, second.StatusCode);
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