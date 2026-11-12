using System.IO.Compression;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Cpio;
using WirDrop.Core.Security;

namespace WirDrop.Core.Archive;

public sealed class UploadLimits
{
    public int MaxEntries { get; init; } = 4096;

    public long MaxTotalBytes { get; init; } = 16L * 1024 * 1024 * 1024;

    public long MaxDecodedBytes { get; init; } = 16L * 1024 * 1024 * 1024;

    public static UploadLimits Default => new();
}

public sealed class UploadException(string message) : Exception(message);

/// <summary>
/// 处理 `/Upload` 请求体：解压（gzip 或 DVZip）→ CPIO 解析 → 按 /Ask 白名单安全解包。
///
/// 安全要点（SEC-1、UP-7）：
/// - 只写 <paramref name="staging"/> 之下的目录；
/// - 每个条目必须对应 /Ask 列出的路径（或其包装目录、AppleDouble 旁车）；
/// - 拒绝符号链接、设备节点、硬链接与重复条目；
/// - TRAILER 到达即完成，差 1 字节也算成功（UP-11）。
/// </summary>
public sealed class UploadExtractor
{
    private enum Plan
    {
        Skip,
        WriteFile,
        WriteDirectory,
    }

    private readonly HashSet<string> _listedFiles = new(StringComparer.Ordinal);
    private readonly HashSet<string> _listedDirectories = new(StringComparer.Ordinal);
    private readonly HashSet<string> _wrappedFolders = new(StringComparer.Ordinal);
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly UploadLimits _limits;
    private readonly List<string> _written = [];

    public UploadExtractor(AskRequest ask, UploadLimits? limits = null)
    {
        _limits = limits ?? UploadLimits.Default;
        foreach (var file in ask.Files)
        {
            // ASK-5：FileBomPath 必须是 ./<FileName> 或 ./<folder>/<FileName>。
            SafeRelativePath parsed;
            try
            {
                parsed = SafeRelativePath.Parse(file.FileBomPath);
            }
            catch (UnsafePathException)
            {
                throw new UploadException($"文件路径不安全：{file.FileBomPath}");
            }

            var path = parsed;
            if (!string.Equals(path.Name.Trim(), file.FileName.Trim(), StringComparison.Ordinal))
            {
                throw new UploadException($"文件路径与文件名不一致：{file.FileName}");
            }

            if (file.FileIsDirectory)
            {
                _listedDirectories.Add(path.ToString());
                continue;
            }

            _listedFiles.Add(path.ToString());
            if (path.Parent is { } parent)
            {
                // 包装目录形式 ./<folder>/<FileName>：目录本身可以出现，但不落盘。
                _wrappedFolders.Add(parent.ToString());
            }
        }
    }

    /// <summary>解包到 <paramref name="staging"/>，返回落地文件的绝对路径列表。</summary>
    public async Task<IReadOnlyList<string>> ExtractAsync(
        Stream body,
        string contentType,
        string staging,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(staging);
        await using var decoded = OpenDecoder(body, contentType);
        var reader = new CpioReader();
        var buffer = new byte[64 * 1024];
        var total = 0L;
        var entries = 0;
        FileStream? current = null;
        var currentPath = string.Empty;
        var completed = false;

        try
        {
            int n;
            while (!completed && (n = await decoded.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                total += n;
                if (total > _limits.MaxDecodedBytes)
                {
                    throw new UploadException("解压后数据超过上限");
                }

                reader.Feed(buffer.AsSpan(0, n));
                while (reader.Pull() is { } ev)
                {
                    switch (ev)
                    {
                        case EntryStarted started:
                        {
                            if (++entries > _limits.MaxEntries)
                            {
                                throw new UploadException("归档条目过多");
                            }

                            var (plan, relative) = Review(started.Entry);
                            if (plan == Plan.WriteDirectory)
                            {
                                var dir = Resolve(staging, relative);
                                Directory.CreateDirectory(dir);
                                break;
                            }

                            if (plan == Plan.Skip)
                            {
                                break;
                            }

                            currentPath = relative;
                            var target = Resolve(staging, relative);
                            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                            current = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
                            break;
                        }

                        case EntryData data:
                            if (current is not null)
                            {
                                if (current.Position + data.Data.Length > _limits.MaxTotalBytes)
                                {
                                    throw new UploadException("单文件超过上限");
                                }

                                await current.WriteAsync(data.Data, ct).ConfigureAwait(false);
                            }

                            break;

                        case EntryEnded:
                            if (current is not null)
                            {
                                await current.DisposeAsync().ConfigureAwait(false);
                                current = null;
                                _written.Add(currentPath);
                            }

                            break;

                        case ArchiveComplete:
                            completed = true;
                            break;
                    }
                }
            }
        }
        finally
        {
            if (current is not null)
            {
                await current.DisposeAsync().ConfigureAwait(false);
            }
        }

        return _written.Select(p => Resolve(staging, p)).ToList();
    }

    /// <summary>复核一个归档条目，决定写入、建目录还是跳过。</summary>
    private (Plan Plan, string Relative) Review(CpioEntry entry)
    {
        var name = entry.Name;
        if (name is "." or "./")
        {
            return (Plan.Skip, string.Empty);
        }

        SafeRelativePath path;
        try
        {
            path = SafeRelativePath.Parse(name);
        }
        catch (UnsafePathException)
        {
            throw new UploadException($"条目名不安全：{name}");
        }

        var key = path.ToString();

        if (entry.Kind == CpioKind.Directory)
        {
            if (entry.Size != 0)
            {
                throw new UploadException($"目录条目带有数据：{name}");
            }

            // 只接受 /Ask 列出的目录或包装目录，不保留包装目录本身。
            if (_listedDirectories.Contains(key))
            {
                return (Plan.WriteDirectory, key);
            }

            if (_wrappedFolders.Contains(key) || (_listedFiles.Count > 0 && prefixOfListed(key)))
            {
                return (Plan.Skip, string.Empty);
            }

            throw new UploadException($"未在 /Ask 中列出的目录：{name}");
        }

        if (entry.Kind != CpioKind.Regular || entry.LinkCount > 1)
        {
            throw new UploadException($"不支持的条目类型：{name}");
        }

        // AppleDouble 旁车（._name）只读取不落盘（UP-7a）。
        if (path.Name.StartsWith("._", StringComparison.Ordinal))
        {
            return (Plan.Skip, string.Empty);
        }

        if (!_listedFiles.Contains(key))
        {
            throw new UploadException($"未在 /Ask 中列出的文件：{name}");
        }

        if (!_seen.Add(key))
        {
            throw new UploadException($"重复条目：{name}");
        }

        return (Plan.WriteFile, key);

        bool prefixOfListed(string candidate)
        {
            var prefix = candidate + "/";
            return _listedFiles.Any(f => f.StartsWith(prefix, StringComparison.Ordinal))
                || _listedDirectories.Any(d => d.StartsWith(prefix, StringComparison.Ordinal) || d == candidate);
        }
    }

    private static string Resolve(string staging, string relative)
    {
        var full = Path.GetFullPath(Path.Combine(staging, relative.Replace('/', Path.DirectorySeparatorChar)));
        var root = Path.GetFullPath(staging) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new UploadException("路径越出临时目录");
        }

        return full;
    }

    private static Stream OpenDecoder(Stream body, string contentType)
    {
        if (contentType.Equals("application/x-dvzip", StringComparison.OrdinalIgnoreCase))
        {
            return new DvZipReadStream(body);
        }

        if (contentType.Equals("application/x-cpio", StringComparison.OrdinalIgnoreCase))
        {
            return new GZipStream(body, CompressionMode.Decompress, leaveOpen: true);
        }

        throw new UploadException($"不支持的 Content-Type：{contentType}");
    }
}

/// <summary>把 DVZip 解码器暴露成只读流。</summary>
internal sealed class DvZipReadStream : Stream
{
    private readonly DvZipDecoder _decoder;

    public DvZipReadStream(Stream inner) => _decoder = new DvZipDecoder(inner);

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => _decoder.Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer) => _decoder.Read(buffer);

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _decoder.Dispose();
        }

        base.Dispose(disposing);
    }
}