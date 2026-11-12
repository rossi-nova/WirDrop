using System.Buffers.Binary;
using System.IO.Compression;

namespace WirDrop.Core.Archive;

/// <summary>
/// DVZip：AirDrop <c>/Upload</c> 的分块压缩流（§6.6）。
///
/// 每一块是 4 字节大端长度 + 该长度的 zlib 流；长度最高位置位表示 stored 块，
/// 其后的数据就是未压缩原文。解码器逐块解压，每次只向调用方交出最多一块的结果，
/// 因此不会把整个归档读进内存。任何一块损坏都拒绝整条流（DVZ-3/DVZ-4）。
/// </summary>
public sealed class DvZipDecoder : IDisposable
{
    private const int HeaderSize = 4;

    private readonly Stream _input;
    private readonly long _maxChunk;
    private readonly int _lastUncompressedLength;
    private readonly byte[] _header = new byte[HeaderSize];
    private Stream? _current;
    private int _headerFill;
    private bool _done;

    /// <param name="input">压缩流（只读）。</param>
    /// <param name="maxChunk">单块解压后的上限，防止压缩炸弹。</param>
    public DvZipDecoder(Stream input, long maxChunk = 64L * 1024 * 1024)
    {
        if (maxChunk <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxChunk));
        }

        _input = input;
        _maxChunk = maxChunk;
        _lastUncompressedLength = 0;
    }

    public bool IsComplete => _done;

    /// <summary>
    /// 读取下一段已解压数据。返回 0 表示流结束。调用方拿到的数据可能只有一块的一部分。
    /// </summary>
    public int Read(Span<byte> buffer)
    {
        var written = 0;
        while (written < buffer.Length && !_done)
        {
            if (_current is null)
            {
                if (!OpenNextChunk())
                {
                    break;
                }
            }

            var n = _current.Read(buffer[written..]);
            if (n == 0)
            {
                // 一块结束；必须正好在块边界上，不能把半截流拼到下一块。
                _current.Dispose();
                _current = null;
                continue;
            }

            written += n;
        }

        return written;
    }

    /// <summary>把解压结果原样拷贝到 <paramref name="destination"/>。</summary>
    public void CopyTo(Stream destination)
    {
        var buffer = new byte[64 * 1024];
        int n;
        while ((n = Read(buffer)) > 0)
        {
            destination.Write(buffer, 0, n);
        }
    }

    private bool OpenNextChunk()
    {
        // 逐字节读 4 字节头；流在块边界处恰好结束是合法的。
        while (_headerFill < HeaderSize)
        {
            var n = _input.Read(_header.AsSpan(_headerFill, HeaderSize - _headerFill));
            if (n == 0)
            {
                if (_headerFill == 0)
                {
                    _done = true;
                    return false;
                }

                throw new InvalidDataException("DVZip 流在块头处意外结束");
            }

            _headerFill += n;
        }

        _headerFill = 0;
        var raw = BinaryPrimitives.ReadUInt32BigEndian(_header);
        var stored = (raw & 0x80000000u) != 0;
        var length = raw & 0x7FFFFFFFu;
        if (length == 0)
        {
            throw new InvalidDataException("DVZip 块长度为 0");
        }

        if (stored)
        {
            if (length > _maxChunk)
            {
                throw new InvalidDataException("DVZip stored 块过大");
            }

            _current = new StoredChunkStream(_input, length);
        }
        else
        {
            // 读入这一块的压缩数据后交给 zlib；单块上限防止内存被撑爆。
            if (length > _maxChunk)
            {
                throw new InvalidDataException("DVZip 压缩块过大");
            }

            var compressed = new byte[length];
            ReadExact(compressed, 0, compressed.Length, "DVZip 压缩块");
            var head = new MemoryStream(compressed, writable: false);
            _current = new ZLibStream(head, CompressionMode.Decompress);
        }

        return true;
    }

    private void ReadExact(byte[] buffer, int offset, int count, string what)
    {
        while (count > 0)
        {
            var n = _input.Read(buffer, offset, count);
            if (n == 0)
            {
                throw new InvalidDataException($"{what}意外结束");
            }

            offset += n;
            count -= n;
        }
    }

    public void Dispose()
    {
        _current?.Dispose();
        _current = null;
    }

    /// <summary>把 stored 块的原始字节当作只读流。</summary>
    private sealed class StoredChunkStream : Stream
    {
        private readonly Stream _underlying;
        private long _left;

        public StoredChunkStream(Stream underlying, long length)
        {
            _underlying = underlying;
            _left = length;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_left == 0)
            {
                return 0;
            }

            var n = _underlying.Read(buffer[..(int)Math.Min(buffer.Length, _left)]);
            if (n == 0)
            {
                throw new InvalidDataException("DVZip stored 块意外结束");
            }

            _left -= n;
            return n;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

/// <summary>
/// DVZip 编码器：把归档按 64 KiB 切片，各自独立压缩；压不动的片段写成 stored 块（DVZ-2）。
/// 只在使用方明确要求时启用（本机默认发 gzip，兼容性最好）。
/// </summary>
public static class DvZipEncoder
{
    public const int PieceSize = 65536;

    public static void Encode(Stream source, Stream destination, int level = 6)
    {
        var piece = new byte[PieceSize];
        var compressed = new MemoryStream();
        while (true)
        {
            var read = source.ReadAtLeast(piece, PieceSize, throwOnEndOfStream: false);
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
                WriteHeader(destination, (uint)compressed.Length);
                destination.Write(compressed.GetBuffer(), 0, (int)compressed.Length);
            }
            else
            {
                WriteHeader(destination, 0x80000000u | (uint)read);
                destination.Write(piece, 0, read);
            }
        }
    }

    private static void WriteHeader(Stream s, uint value)
    {
        Span<byte> h = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(h, value);
        s.Write(h);
    }
}
