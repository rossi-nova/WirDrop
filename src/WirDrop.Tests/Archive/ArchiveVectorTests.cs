using System.Security.Cryptography;
using WirDrop.Core.Archive;
using WirDrop.Core.Cpio;
using WirDrop.Tests.Support;

namespace WirDrop.Tests.Archive;

/// <summary>用 OpenDrop/Owly 的字节级向量校验本实现的 DVZip 与 CPIO 解析。</summary>
public class ArchiveVectorTests
{
    [Fact]
    public void DvZipDecoderMatchesVectors()
    {
        var count = 0;
        foreach (var v in Vectors.Of("dvzip"))
        {
            var input = Vectors.B64(v, "input_b64");
            using var decoder = new DvZipDecoder(new MemoryStream(input));
            using var output = new MemoryStream();
            decoder.CopyTo(output);

            var expected = v.GetProperty("expect");
            var expectLen = expected.GetProperty("output_len").GetInt64();
            Assert.True(expectLen == output.Length, $"{Vectors.Name(v)}: 期望 {expectLen} 字节，实际 {output.Length}");
            var sha = Convert.ToHexString(SHA256.HashData(output.ToArray())).ToLowerInvariant();
            Assert.Equal(expected.GetProperty("output_sha256").GetString(), sha);

            // 自己的编码器再编一次，确认能原样解回。
            var encoded = new MemoryStream();
            DvZipEncoder.Encode(new MemoryStream(output.ToArray()), encoded);
            var again = new MemoryStream();
            using (var d2 = new DvZipDecoder(new MemoryStream(encoded.ToArray())))
            {
                d2.CopyTo(again);
            }

            Assert.Equal(output.ToArray(), again.ToArray());
            count++;
        }

        Assert.True(count >= 4);
    }

    [Fact]
    public void CpioReaderMatchesVectors()
    {
        var ran = 0;
        foreach (var v in Vectors.Of("cpio"))
        {
            var input = Vectors.B64(v, "input_b64");
            var reader = new CpioReader();
            reader.Feed(input);
            var files = Collect(reader);

            var expected = v.GetProperty("expect").GetProperty("files").EnumerateArray().ToList();
            Assert.True(expected.Count == files.Count,
                $"{Vectors.Name(v)}: 期望 {expected.Count} 个文件，实际 {files.Count}");
            for (var i = 0; i < expected.Count; i++)
            {
                var e = expected[i];
                Assert.Equal(e.GetProperty("path").GetString(), files[i].Path);
                Assert.Equal(e.GetProperty("mode").GetInt32(), files[i].Mode);
                Assert.Equal(Vectors.B64(e, "data_b64"), files[i].Data);
            }

            ran++;
        }

        Assert.True(ran >= 4);
    }

    [Fact]
    public void CpioReaderHandlesChunkedInput()
    {
        // 每次只喂 1~3 个字节，结果必须与一次性喂完相同。
        foreach (var v in Vectors.Of("cpio"))
        {
            var input = Vectors.B64(v, "input_b64");
            var reader = new CpioReader();
            reader.Feed(input);
            var whole = Collect(reader);

            var chunked = new CpioReader();
            var chunkSize = 1;
            var at = 0;
            while (at < input.Length && !chunked.IsComplete)
            {
                var n = Math.Min(chunkSize, input.Length - at);
                chunked.Feed(input.AsSpan(at, n));
                at += n;
                chunkSize = chunkSize == 3 ? 1 : chunkSize + 1;
            }

            var chunkedFiles = Collect(chunked);
            Assert.Equal(whole.Count, chunkedFiles.Count);
            for (var i = 0; i < whole.Count; i++)
            {
                Assert.Equal(whole[i].Path, chunkedFiles[i].Path);
                Assert.Equal(whole[i].Mode, chunkedFiles[i].Mode);
                Assert.Equal(whole[i].Data, chunkedFiles[i].Data);
            }
        }
    }

    private static List<(string Path, byte[] Data, int Mode)> Collect(CpioReader reader)
    {
        var files = new List<(string Path, byte[] Data, int Mode)>();
        using var content = new MemoryStream();
        CpioEntry? cur = null;
        while (reader.Pull() is { } ev)
        {
            switch (ev)
            {
                case EntryStarted s when s.Entry.Name != ".":
                    Assert.Equal(CpioKind.Regular, s.Entry.Kind);
                    cur = s.Entry;
                    content.SetLength(0);
                    break;
                case EntryData d:
                    content.Write(d.Data.Span);
                    break;
                case EntryEnded when cur is not null:
                    files.Add((cur.Name, content.ToArray(), cur.Permissions));
                    cur = null;
                    break;
            }
        }

        return files;
    }
}
