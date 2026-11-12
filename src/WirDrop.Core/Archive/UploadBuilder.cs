using System.IO.Compression;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Cpio;
using WirDrop.Core.Security;

namespace WirDrop.Core.Archive;

/// <summary>
/// 把一批文件（或链接）打包装进 `application/x-cpio`（gzip + odc 或 DVZip）。
/// 链接分享按 §6.4 打成 <c>.webloc</c> 条目而不上传内容（ASK-4）。
/// </summary>
public static class UploadBuilder
{
    public sealed class PreparedUpload : IAsyncDisposable
    {
        public required string Path { get; init; }

        public required long Length { get; init; }

        public required IReadOnlyList<AskFile> Files { get; init; }

        public ValueTask DisposeAsync()
        {
            try
            {
                if (Path.Length > 0)
                {
                    File.Delete(Path);
                }
            }
            catch (IOException)
            {
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>打包文件或目录；<paramref name="dvzip"/> 为 true 时用 application/x-dvzip。</summary>
    public static async Task<PreparedUpload> PrepareFilesAsync(IReadOnlyList<string> paths, bool dvzip, CancellationToken ct = default)
    {
        var temp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"wirdrop-upload-{Guid.NewGuid():N}.archive");
        var files = new List<AskFile>();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var writer = new OdcWriter();
        var inode = 2;
        try
        {
            await using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.Asynchronous))
            {
                if (dvzip)
                {
                    // 先生成 gzip 无关的原始 odc，再分块压缩（DVZ-2）。
                    using var raw = new MemoryStream();
                    await WriteArchiveAsync(raw, paths, writer, files, now, inode, ct).ConfigureAwait(false);
                    raw.Position = 0;
                    DvZipEncoder.Encode(raw, file);
                }
                else
                {
                    await using var gzip = new GZipStream(file, CompressionLevel.Fastest, leaveOpen: true);
                    await WriteArchiveAsync(gzip, paths, writer, files, now, inode, ct).ConfigureAwait(false);
                }
            }

            return new PreparedUpload { Path = temp, Length = new FileInfo(temp).Length, Files = files };
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
    }

    /// <summary>链接分享：把 URL 写成 webloc 条目元数据（从不发送 /Upload，ASK-4）。</summary>
    public static PreparedUpload PrepareLinks(IReadOnlyList<string> urls)
    {
        var files = urls.Select((url, i) => new AskFile
        {
            FileName = $"链接 {i + 1}.webloc",
            FileType = "com.apple.web-internet-location",
            FileBomPath = $"./链接 {i + 1}.webloc",
            FileIsDirectory = false,
            FileSize = 0,
        }).ToList();
        return new PreparedUpload { Path = string.Empty, Length = 0, Files = files };
    }

    /// <summary>DVZip 编码：每块解压后按 zlib 独立压缩，压不动的写成 stored 块。</summary>
    public static void EncodeDvZip(Stream source, Stream destination)
    {
        var piece = new byte[65536];
        var compressed = new MemoryStream();
        Span<byte> header = stackalloc byte[4];
        while (true)
        {
            var read = source.ReadAtLeast(piece, piece.Length, throwOnEndOfStream: false);
            if (read == 0)
            {
                break;
            }

            compressed.SetLength(0);
            using (var z = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
            {
                z.Write(piece, 0, read);
            }

            if (compressed.Length < read)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header, (uint)compressed.Length);
                destination.Write(header);
                destination.Write(compressed.GetBuffer(), 0, (int)compressed.Length);
            }
            else
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header, 0x80000000u | (uint)read);
                destination.Write(header);
                destination.Write(piece, 0, read);
            }
        }
    }

    private static async Task WriteArchiveAsync(
        Stream body,
        IReadOnlyList<string> paths,
        OdcWriter writer,
        List<AskFile> files,
        long now,
        int inode,
        CancellationToken ct)
    {
        body.Write(OdcWriter.RootHeader(now));
        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            if (Directory.Exists(path))
            {
                var rootName = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
                body.Write(OdcWriter.DirectoryHeader("./" + rootName, now, (uint)inode++));
                foreach (var entry in EnumerateDirectory(path))
                {
                    var bomPath = "./" + rootName + "/" + entry.Relative;
                    if (entry.IsDirectory)
                    {
                        body.Write(OdcWriter.DirectoryHeader(bomPath, now, (uint)inode++));
                    }
                    else
                    {
                        body.Write(writer.FileHeader(bomPath, new FileInfo(entry.Full).Length, now));
                        await using var source = new FileStream(entry.Full, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.Asynchronous);
                        await source.CopyToAsync(body, 1 << 20, ct).ConfigureAwait(false);
                    }

                    files.Add(MakeAskFile(bomPath, entry.Full, entry.IsDirectory));
                }
            }
            else
            {
                var name = WindowsName.Sanitize(Path.GetFileName(path));
                var bomPath = "./" + name;
                body.Write(writer.FileHeader(bomPath, new FileInfo(path).Length, now));
                await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.Asynchronous);
                await source.CopyToAsync(body, 1 << 20, ct).ConfigureAwait(false);
                files.Add(MakeAskFile(bomPath, path, false));
            }
        }

        body.Write(OdcWriter.TrailerHeader());
        body.Flush();
    }

    private static AskFile MakeAskFile(string bomPath, string fullPath, bool isDirectory)
    {
        var name = bomPath.Split('/').Last();
        return new AskFile
        {
            FileName = name,
            FileType = isDirectory ? "public.folder" : UniformTypes.ForFile(fullPath),
            FileBomPath = bomPath,
            FileIsDirectory = isDirectory,
            FileSize = isDirectory ? 0 : new FileInfo(fullPath).Length,
            ShouldConvertMediaFormats = false,
        };
    }

    private sealed record TreeEntry(string Relative, string Full, bool IsDirectory);

    private static IEnumerable<TreeEntry> EnumerateDirectory(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                if (new DirectoryInfo(sub).LinkTarget is not null)
                {
                    continue; // 不跟随符号链接
                }

                stack.Push(sub);
                yield return new TreeEntry(RelPath(root, sub), sub, true);
            }

            foreach (var file in Directory.EnumerateFiles(dir))
            {
                yield return new TreeEntry(RelPath(root, file), file, false);
            }
        }
    }

    private static string RelPath(string root, string path) =>
        Path.GetRelativePath(root, path).Replace('\\', '/');

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }
}