using System.Text.Json;

namespace WirDrop.Tests.Support;

/// <summary>
/// 读取 OpenDrop / Owly 的 airdrop-vectors.json（测试项目里的 Resources 副本）。
/// 内容是重建的协议报文样例：DVZip 流、CPIO 归档、/Discover /Ask /Upload 请求及期望解析结果。
/// </summary>
public static class AirdropVectors
{
    private static readonly Lazy<JsonDocument> Document = new(() =>
        JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Resources", "airdrop-vectors.json"))));

    public static JsonElement Root => Document.Value.RootElement;

    public static JsonElement Constants => Root.GetProperty("constants");
}

public static class Vectors
{
    public static List<JsonElement> Of(string kind) => Root(kind).EnumerateArray().ToList();

    private static JsonElement Root(string kind) => AirdropVectors.Root.GetProperty(kind);

    public static byte[] B64(JsonElement e, string prop) =>
        Convert.FromBase64String(e.GetProperty(prop).GetString()!);

    public static string Name(JsonElement e) => e.GetProperty("name").GetString()!;
}
