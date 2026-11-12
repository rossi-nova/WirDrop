using System.Text;
using System.Text.Json;
using WirDrop.Core.Plist;

namespace WirDrop.Core.AirDrop;

/// <summary>接收端能力位（MDNS-4）。</summary>
[Flags]
public enum ReceiverFlags
{
    None = 0,
    SupportsUrl = 0x001,
    SupportsDvZip = 0x002,
    SupportsPipelining = 0x004,
    SupportsMixedTypes = 0x008,
    SupportsIris = 0x040,
    SupportsDiscoverMaybe = 0x080,
    SupportsAssetBundle = 0x200,

    /// <summary>最小可用集合：URL + 混合类型 + /Discover（MDNS-5 的 0x089）。</summary>
    Minimal = SupportsUrl | SupportsMixedTypes | SupportsDiscoverMaybe,
}

/// <summary>UTI 映射：尽量给对端一个可识别的类型，避免被当成 public.data。</summary>
public static class UniformTypes
{
    private static readonly Dictionary<string, string> ByExtension = new(StringComparer.OrdinalIgnoreCase)
    {
        [".jpg"] = "public.jpeg", [".jpeg"] = "public.jpeg", [".heic"] = "public.heic",
        [".png"] = "public.png", [".gif"] = "com.compuserve.gif", [".tif"] = "public.tiff", [".tiff"] = "public.tiff",
        [".webp"] = "org.webmproject.webp", [".bmp"] = "com.microsoft.bmp", [".svg"] = "public.svg-image",
        [".raw"] = "public.camera-raw-image", [".dng"] = "com.adobe.digital-negative",
        [".pdf"] = "com.adobe.pdf", [".txt"] = "public.plain-text", [".md"] = "net.daringfireball.markdown",
        [".rtf"] = "public.rtf", [".doc"] = "com.microsoft.word.doc", [".docx"] = "org.openxmlformats.wordprocessingml.document",
        [".xls"] = "com.microsoft.excel.xls", [".xlsx"] = "org.openxmlformats.spreadsheetml.sheet",
        [".ppt"] = "com.microsoft.powerpoint.ppt", [".pptx"] = "org.openxmlformats.presentationml.presentation",
        [".pages"] = "com.apple.iwork.pages.pages", [".numbers"] = "com.apple.iwork.numbers.numbers",
        [".key"] = "com.apple.iwork.keynote.key",
        [".mp3"] = "public.mp3", [".m4a"] = "public.mpeg-4-audio", [".wav"] = "com.microsoft.waveform-audio",
        [".aiff"] = "public.aiff-audio", [".flac"] = "org.xiph.flac",
        [".mp4"] = "public.mpeg-4", [".m4v"] = "com.apple.m4v-video", [".mov"] = "com.apple.quicktime-movie",
        [".avi"] = "public.avi", [".mkv"] = "org.matroska.mkv",
        [".zip"] = "public.zip-archive", [".gz"] = "org.gnu.gnu-zip-archive", [".tar"] = "public.tar-archive",
        [".7z"] = "org.7-zip.7-zip-archive", [".rar"] = "com.rarlab.rar-archive",
        [".html"] = "public.html", [".htm"] = "public.html", [".xml"] = "public.xml", [".json"] = "public.json",
        [".csv"] = "public.comma-separated-values-text", [".vcf"] = "public.vcard",
        [".epub"] = "org.idpf.epub-container", [".ics"] = "com.apple.ical.ics",
        [".app"] = "com.apple.application-bundle", [".dmg"] = "com.apple.disk-image",
        [".exe"] = "public.executable", [".apk"] = "com.android.package-archive",
    };

    public static string ForFile(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Length > 0 && ByExtension.TryGetValue(ext, out var uti))
        {
            return uti;
        }

        return Directory.Exists(path) ? "public.folder" : "public.data";
    }
}

/// <summary>`/Discover` 请求（§6.3）：可以为空字典。</summary>
public sealed class DiscoverRequest
{
    public byte[]? SenderRecordData { get; init; }

    public string? SenderComputerName { get; init; }

    public string? SenderModelName { get; init; }

    public string? SenderId { get; init; }

    public byte[] ToPlist()
    {
        var dict = new Dictionary<string, object?>();
        if (SenderRecordData is not null)
        {
            dict["SenderRecordData"] = SenderRecordData;
        }

        if (SenderComputerName is not null)
        {
            dict["SenderComputerName"] = SenderComputerName;
        }

        if (SenderModelName is not null)
        {
            dict["SenderModelName"] = SenderModelName;
        }

        if (SenderId is not null)
        {
            dict["SenderID"] = SenderId;
        }

        return BinaryPlist.Serialize(dict);
    }

    public static DiscoverRequest Parse(byte[] plist)
    {
        var dict = BinaryPlist.Parse(plist) as Dictionary<string, object?>
                   ?? throw new FormatException("/Discover 请求不是字典");
        return new DiscoverRequest
        {
            SenderRecordData = dict.GetValueOrDefault("SenderRecordData") as byte[],
            SenderComputerName = dict.GetValueOrDefault("SenderComputerName") as string,
            SenderModelName = dict.GetValueOrDefault("SenderModelName") as string,
            SenderId = dict.GetValueOrDefault("SenderID") as string,
        };
    }
}

/// <summary>`/Discover` 响应（§6.3）。只有带 ReceiverComputerName 才表示可见（DISC-1）。</summary>
public sealed class DiscoverResponse
{
    public int? StatusCode { get; init; }

    public string? ReceiverComputerName { get; init; }

    public string? ReceiverModelName { get; init; }

    /// <summary>UTF-8 JSON，不是 plist。</summary>
    public string? ReceiverMediaCapabilities { get; init; }

    public byte[]? ReceiverRecordData { get; init; }

    public bool Visible => ReceiverComputerName is not null;

    public byte[] ToPlist()
    {
        var dict = new Dictionary<string, object?>();
        if (StatusCode is not null)
        {
            dict["StatusCode"] = StatusCode.Value;
        }

        if (ReceiverComputerName is not null)
        {
            dict["ReceiverComputerName"] = ReceiverComputerName;
        }

        if (ReceiverModelName is not null)
        {
            dict["ReceiverModelName"] = ReceiverModelName;
        }

        if (ReceiverMediaCapabilities is not null)
        {
            dict["ReceiverMediaCapabilities"] = Encoding.UTF8.GetBytes(ReceiverMediaCapabilities);
        }

        if (ReceiverRecordData is not null)
        {
            dict["ReceiverRecordData"] = ReceiverRecordData;
        }

        return BinaryPlist.Serialize(dict);
    }

    public static DiscoverResponse Parse(byte[] plist)
    {
        var dict = BinaryPlist.Parse(plist) as Dictionary<string, object?>
                   ?? throw new FormatException("/Discover 响应不是字典");
        return new DiscoverResponse
        {
            StatusCode = dict.GetValueOrDefault("StatusCode") is int code ? code : null,
            ReceiverComputerName = dict.GetValueOrDefault("ReceiverComputerName") as string,
            ReceiverModelName = dict.GetValueOrDefault("ReceiverModelName") as string,
            ReceiverMediaCapabilities = dict.GetValueOrDefault("ReceiverMediaCapabilities") is byte[] caps
                ? Encoding.UTF8.GetString(caps)
                : null,
            ReceiverRecordData = dict.GetValueOrDefault("ReceiverRecordData") as byte[],
        };
    }
}

/// <summary>`/Ask` 中 Files[] 的一个条目（§6.4）。</summary>
public sealed class AskFile
{
    public required string FileName { get; init; }

    public required string FileType { get; init; }

    public required string FileBomPath { get; init; }

    public bool FileIsDirectory { get; init; }

    public long FileSize { get; init; }

    public bool ShouldConvertMediaFormats { get; init; }
}

/// <summary>发送方在 `/Ask` 里提出的请求。</summary>
public sealed class AskRequest
{
    public string? TransferId { get; init; }

    public required string SenderComputerName { get; init; }

    public required string SenderModelName { get; init; }

    public required string SenderId { get; init; }

    public string BundleId { get; init; } = "com.apple.finder";

    public IReadOnlyList<AskFile> Files { get; init; } = [];

    /// <summary>链接分享时非空；与 Files 互斥。</summary>
    public IReadOnlyList<string> Items { get; init; } = [];

    public byte[]? FileIcon { get; init; }

    public byte[]? SenderRecordData { get; init; }

    public bool IsLinkShare => Items.Count > 0;

    public byte[] ToPlist()
    {
        var dict = new Dictionary<string, object?>
        {
            ["BundleID"] = BundleId,
            ["ConvertMediaFormats"] = false,
            ["SenderComputerName"] = SenderComputerName,
            ["SenderModelName"] = SenderModelName,
            ["SenderID"] = SenderId,
        };
        if (TransferId is not null)
        {
            dict["TransferID"] = new Dictionary<string, object?> { ["id"] = TransferId };
        }

        // 其他实现（含 iOS）都发送当前形态；即使没有 TransferId 也带上 TransferType。
        var kind = IsLinkShare ? "links" : "files";
        dict["TransferType"] = new Dictionary<string, object?> { [kind] = new Dictionary<string, object?>() };
        var files = new List<object?>();
        foreach (var f in Files)
        {
            files.Add(new Dictionary<string, object?>
            {
                ["FileName"] = f.FileName,
                ["FileType"] = f.FileType,
                ["FileBomPath"] = f.FileBomPath,
                ["FileIsDirectory"] = f.FileIsDirectory,
                ["FileSize"] = f.FileSize,
                ["ShouldConvertMediaFormats"] = f.ShouldConvertMediaFormats,
            });
        }

        dict["Files"] = files;
        dict["Items"] = Items.Cast<object?>().ToList();
        if (FileIcon is not null)
        {
            dict["FileIcon"] = FileIcon;
        }

        if (SenderRecordData is not null)
        {
            dict["SenderRecordData"] = SenderRecordData;
        }

        return BinaryPlist.Serialize(dict);
    }

    public static AskRequest Parse(byte[] plist)
    {
        var dict = BinaryPlist.Parse(plist) as Dictionary<string, object?>
                   ?? throw new FormatException("/Ask 请求不是字典");
        var files = (dict.GetValueOrDefault("Files") as List<object?> ?? [])
            .OfType<Dictionary<string, object?>>()
            .Select(d => new AskFile
            {
                FileName = d.GetValueOrDefault("FileName") as string ?? LatestName(d),
                FileType = d.GetValueOrDefault("FileType") as string ?? "public.data",
                FileBomPath = d.GetValueOrDefault("FileBomPath") as string ?? "./" + (d.GetValueOrDefault("FileName") as string ?? ""),
                FileIsDirectory = d.GetValueOrDefault("FileIsDirectory") is bool isDir && isDir,
                FileSize = d.GetValueOrDefault("FileSize") is long size ? size
                    : d.GetValueOrDefault("FileSize") is int small ? small : 0,
                ShouldConvertMediaFormats = d.GetValueOrDefault("ShouldConvertMediaFormats") is bool conv && conv,
            })
            .ToList();
        var items = (dict.GetValueOrDefault("Items") as List<object?> ?? []).OfType<string>().ToList();
        string? transferId = dict.GetValueOrDefault("TransferID") switch
        {
            string s => s,
            Dictionary<string, object?> t => t.GetValueOrDefault("id") as string,
            _ => null,
        };
        return new AskRequest
        {
            TransferId = transferId,
            SenderComputerName = dict.GetValueOrDefault("SenderComputerName") as string ?? "",
            SenderModelName = dict.GetValueOrDefault("SenderModelName") as string ?? "",
            SenderId = dict.GetValueOrDefault("SenderID") as string ?? "",
            BundleId = dict.GetValueOrDefault("BundleID") as string ?? "com.apple.finder",
            Files = files,
            Items = items,
            FileIcon = dict.GetValueOrDefault("FileIcon") as byte[],
            SenderRecordData = dict.GetValueOrDefault("SenderRecordData") as byte[],
        };
    }

    private static string LatestName(Dictionary<string, object?> d) =>
        (d.GetValueOrDefault("FileBomPath") as string ?? "").Split('/').Last();
}

/// <summary>`/Ask` 的应答：接收方名称与型号。</summary>
public sealed class AskResponse
{
    public required string ReceiverComputerName { get; init; }

    public required string ReceiverModelName { get; init; }

    public byte[] ToPlist() => BinaryPlist.Serialize(new Dictionary<string, object?>
    {
        ["ReceiverComputerName"] = ReceiverComputerName,
        ["ReceiverModelName"] = ReceiverModelName,
    });
}

/// <summary>媒体能力 JSON（DISC-3）：只声明版本，不声明编解码器，换取最通用格式。</summary>
public static class MediaCapabilities
{
    public static string Default =>
        JsonSerializer.Serialize(new Dictionary<string, object> { ["Version"] = 1 });
}