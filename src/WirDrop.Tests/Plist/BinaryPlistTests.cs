using System.Text;
using WirDrop.Core.Plist;

namespace WirDrop.Tests;

public class BinaryPlistTests
{
    [Fact]
    public void RoundTripsNestedDictionary()
    {
        var value = new Dictionary<string, object?>
        {
            ["BundleID"] = "com.apple.finder",
            ["ConvertMediaFormats"] = false,
            ["Files"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["FileName"] = "写真.png",
                    ["FileType"] = "public.png",
                    ["FileBomPath"] = "./写真.png",
                    ["FileIsDirectory"] = false,
                    ["FileSize"] = 12345,
                    ["ShouldConvertMediaFormats"] = false,
                },
            },
            ["Items"] = new List<object?>(),
            ["SenderComputerName"] = "WirDrop",
            ["SenderID"] = "486ac2a94ac6",
            ["SenderModelName"] = "Windows PC",
            ["TransferID"] = new Dictionary<string, object?> { ["id"] = "A3F34E01-0000-4000-8000-000000000001" },
            ["TransferType"] = new Dictionary<string, object?> { ["files"] = new Dictionary<string, object?>() },
        };

        var bytes = BinaryPlist.Serialize(value);
        Assert.True(BinaryPlist.LooksLikeBinaryPlist(bytes));
        var parsed = BinaryPlist.Parse(bytes) as Dictionary<string, object?>;
        Assert.NotNull(parsed);
        Assert.Equal("com.apple.finder", parsed!["BundleID"]);
        Assert.Equal(false, parsed["ConvertMediaFormats"]);
        var files = Assert.IsAssignableFrom<List<object?>>(parsed["Files"]);
        var file = Assert.IsAssignableFrom<Dictionary<string, object?>>(files[0]);
        Assert.Equal("写真.png", file["FileName"]);
        Assert.Equal(12345, Assert.IsType<int>(file["FileSize"]));
        Assert.Equal("A3F34E01-0000-4000-8000-000000000001",
            ((Dictionary<string, object?>)parsed["TransferID"]!)["id"]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(127)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(65535)]
    [InlineData(65536)]
    public void RoundTripsIntegers(int value)
    {
        var bytes = BinaryPlist.Serialize(new Dictionary<string, object?> { ["v"] = value });
        var parsed = (Dictionary<string, object?>)BinaryPlist.Parse(bytes)!;
        Assert.Equal(value, Assert.IsType<int>(parsed["v"]));
    }

    [Fact]
    public void RoundTripsNegativeAsInt64()
    {
        var bytes = BinaryPlist.Serialize(new Dictionary<string, object?> { ["v"] = -1 });
        var parsed = (Dictionary<string, object?>)BinaryPlist.Parse(bytes)!;
        Assert.Equal(-1L, Assert.IsType<long>(parsed["v"]));
    }

    [Fact]
    public void ReadsAppleSignedBytes()
    {
        // Apple 把 0–255 写成 1 字节无符号，把 256–65535 写成 2 字节无符号。
        Assert.Equal(255, ReadOneByte(0x10, 0xFF));
        Assert.Equal(65535, ReadTwoBytes(0x11, 0xFF, 0xFF));
        Assert.Equal(200, ReadOneByte(0x10, 0xC8));
    }

    private static int ReadOneByte(byte marker, byte v)
    {
        var dict = new MemoryStream();
        dict.Write("bplist00"u8);
        // 对象 0：顶层字典 { "v": 1 }，1 字节引用。
        dict.Write([0xD1, 0x01, 0x02]);
        // 对象 1：键 "v"。
        dict.Write([0x51, (byte)'v']);
        // 对象 2：整数。
        dict.WriteByte(marker);
        dict.WriteByte(v);
        var table = (int)dict.Position;
        foreach (var off in new[] { 8, 11, 13 })
        {
            dict.WriteByte((byte)off);
        }

        dict.Write(new byte[8]);
        dict.WriteByte(1);
        dict.WriteByte(1);
        dict.Write(Be64(3));
        dict.Write(Be64(0));
        dict.Write(Be64((ulong)table));
        var parsed = (Dictionary<string, object?>)BinaryPlist.Parse(dict.ToArray())!;
        return Assert.IsType<int>(parsed["v"]);
    }

    private static int ReadTwoBytes(byte marker, byte hi, byte lo)
    {
        var dict = new MemoryStream();
        dict.Write("bplist00"u8);
        dict.Write([0xD1, 0x01, 0x02]);
        dict.Write([0x51, (byte)'v']);
        dict.WriteByte(marker);
        dict.WriteByte(hi);
        dict.WriteByte(lo);
        var table = (int)dict.Position;
        foreach (var off in new[] { 8, 11, 13 })
        {
            dict.WriteByte((byte)off);
        }

        dict.Write(new byte[8]);
        dict.WriteByte(1);
        dict.WriteByte(1);
        dict.Write(Be64(3));
        dict.Write(Be64(0));
        dict.Write(Be64((ulong)table));
        var parsed = (Dictionary<string, object?>)BinaryPlist.Parse(dict.ToArray())!;
        return Assert.IsType<int>(parsed["v"]);
    }

    [Fact]
    public void RoundTripsLargeData()
    {
        var data = new byte[70_000];
        Random.Shared.NextBytes(data);
        var bytes = BinaryPlist.Serialize(new Dictionary<string, object?> { ["d"] = data });
        var parsed = (Dictionary<string, object?>)BinaryPlist.Parse(bytes)!;
        Assert.Equal(data, parsed["d"]);
    }

    [Fact]
    public void ParsesUnicodeViaUtf16()
    {
        var bytes = BinaryPlist.Serialize(new Dictionary<string, object?> { ["n"] = "iPhone の写真📷" });
        var parsed = (Dictionary<string, object?>)BinaryPlist.Parse(bytes)!;
        Assert.Equal("iPhone の写真📷", parsed["n"]);
    }

    [Fact]
    public void RejectsXmlPlist()
    {
        const string xml = "<?xml version=\"1.0\"?><plist><dict/></plist>";
        Assert.False(BinaryPlist.LooksLikeBinaryPlist(Encoding.UTF8.GetBytes(xml)));
        Assert.Throws<FormatException>(() => BinaryPlist.Parse(Encoding.UTF8.GetBytes(xml)));
    }

    [Fact]
    public void RejectsTruncatedPayload()
    {
        var bytes = BinaryPlist.Serialize(new Dictionary<string, object?> { ["a"] = "abcdefghij" });
        Assert.Throws<FormatException>(() => BinaryPlist.Parse(bytes.AsSpan(0, bytes.Length / 2)));
    }

    [Fact]
    public void RejectsDeepNesting()
    {
        // 手工构造一个 200 层嵌套的数组。
        var writer = new MemoryStream();
        writer.Write("bplist00"u8);
        var objOffsets = new List<int>();
        for (var i = 0; i < 200; i++)
        {
            objOffsets.Add((int)writer.Position);
            writer.WriteByte(0xA1); // 单元素数组
            writer.WriteByte((byte)Math.Min(i + 1, 199));
        }

        objOffsets.Add((int)writer.Position);
        writer.WriteByte(0x09); // true
        var table = (int)writer.Position;
        foreach (var off in objOffsets)
        {
            writer.Write(new byte[2]);
            writer.WriteByte((byte)(off & 0xFF));
        }

        writer.Write(new byte[8]);
        writer.WriteByte(2);
        writer.WriteByte(1);
        writer.Write(Be64((ulong)objOffsets.Count));
        writer.Write(Be64(0));
        writer.Write(Be64((ulong)table));

        Assert.Throws<FormatException>(() => BinaryPlist.Parse(writer.ToArray()));
    }

    private static byte[] Be64(ulong v) =>
        [(byte)(v >> 56), (byte)(v >> 48), (byte)(v >> 40), (byte)(v >> 32),
         (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
}
