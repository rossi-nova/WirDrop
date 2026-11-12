using System.Net;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Net;

namespace WirDrop.Tests.AirDrop;

/// <summary>端到端：本机接收端 ↔ 本机发送端，走真实 TLS + HTTP + CPIO 全链路。</summary>
public class LoopbackTransferTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "wirdrop-e2e-" + Guid.NewGuid().ToString("N"));

    public LoopbackTransferTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task ServerAnnouncesAndAcceptsDiscover()
    {
        var iface = new NetworkInterfaceInfo
        {
            Id = "loopback",
            Name = "loopback",
            Index = 0,
            Address = IPAddress.Loopback,
            Addresses = [IPAddress.Loopback],
        };
        await using var server = new AirDropServer(iface, 18771, "WirDrop Test", Path.Combine(_root, "downloads"));
        server.Start();
        Assert.True(server.ActualPort > 0);

        var sender = new AirDropSender(iface, "WirDrop Sender", "0123456789ab");
        var response = await sender.DiscoverAsync(new IPEndPoint(IPAddress.Loopback, server.ActualPort));
        Assert.NotNull(response);
        Assert.Equal("WirDrop Test", response!.ReceiverComputerName);
        Assert.Equal(100, response.StatusCode);
    }

    [Fact]
    public async Task FullTransferMovesFileIntact()
    {
        var iface = new NetworkInterfaceInfo
        {
            Id = "loopback",
            Name = "loopback",
            Index = 0,
            Address = IPAddress.Loopback,
            Addresses = [IPAddress.Loopback],
        };
        var downloads = Path.Combine(_root, "downloads");
        await using var server = new AirDropServer(iface, 18871, "WirDrop Receiver", downloads);
        server.AskReceived += (_, ask) => _ = Task.Run(() => ask.Decision.TrySetResult(true));
        string? completedFile = null;
        var completed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        server.TransferCompleted += (_, e) =>
        {
            if (e.Files.Count > 0)
            {
                completedFile = e.Files[0];
                completed.TrySetResult(e.Files[0]);
            }
        };
        server.Diagnostic += (_, m) => System.IO.File.AppendAllText(Path.Combine(Path.GetTempPath(), "wd-srv.txt"), m + Environment.NewLine);
        server.Start();

        var payload = new byte[300_000];
        Random.Shared.NextBytes(payload);
        var source = Path.Combine(_root, "sample.bin");
        await File.WriteAllBytesAsync(source, payload);

        var sender = new AirDropSender(iface, "WirDrop Sender", "0123456789ab");
        var result = await sender.SendAsync(
            new IPEndPoint(IPAddress.Loopback, server.ActualPort),
            [source]);

        Assert.True(result.Status == SendStatus.Succeeded, result.Message);
        var received = await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        completedFile ??= received;
        Assert.True(File.Exists(received));
        Assert.Equal(payload, await File.ReadAllBytesAsync(received));
    }

    [Fact]
    public async Task DeclineReturnsDeclined()
    {
        var iface = new NetworkInterfaceInfo
        {
            Id = "loopback",
            Name = "loopback",
            Index = 0,
            Address = IPAddress.Loopback,
            Addresses = [IPAddress.Loopback],
        };
        await using var server = new AirDropServer(iface, 18971, "WirDrop Receiver", Path.Combine(_root, "downloads"));
        server.AskReceived += (_, ask) => _ = Task.Run(() => ask.Decision.TrySetResult(false));
        server.Start();

        var source = Path.Combine(_root, "declined.txt");
        await File.WriteAllTextAsync(source, "no thanks");
        var sender = new AirDropSender(iface, "WirDrop Sender", "0123456789ab");
        var result = await sender.SendAsync(new IPEndPoint(IPAddress.Loopback, server.ActualPort), [source]);
        Assert.Equal(SendStatus.Declined, result.Status);
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