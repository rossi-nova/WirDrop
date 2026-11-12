using System.Text;

namespace WirDrop.Core.Cpio;

/// <summary>CPIO 条目类型。</summary>
public enum CpioKind
{
    Regular,
    Directory,

    /// <summary>符号链接、设备节点、FIFO、socket 等：接收端一律拒绝（SEC-1）。</summary>
    Other,
}

/// <summary>从 CPIO 流里读到的一个条目头（数据尚未读取）。Permissions 为完整 st_mode。</summary>
public sealed record CpioEntry(string Name, CpioKind Kind, int Permissions, long Size, uint LinkCount, uint Inode);

/// <summary>读取器产出的事件。</summary>
public abstract record CpioEvent;

public sealed record EntryStarted(CpioEntry Entry) : CpioEvent;

public sealed record EntryData(ReadOnlyMemory<byte> Data) : CpioEvent;

/// <summary>条目的数据（含 newc 的对齐填充）已全部读完。</summary>
public sealed record EntryEnded : CpioEvent;

/// <summary>TRAILER!!! 条目：归档已结束，后面的字节忽略（UP-11）。</summary>
public sealed record ArchiveComplete : CpioEvent;

public enum CpioFormat
{
    Odc,
    Newc,
}

/// <summary>
/// 流式 CPIO 读取器，支持 AirDrop 发送端使用的 odc（070707，76 字节八进制头）
/// 与 newc（070701，110 字节十六进制头）。
///
/// 实现是"内部缓冲 + 拉取"模型：<see cref="Feed"/> 把新字节追加进缓冲，
/// <see cref="Pull"/> 从缓冲里按需解析并返回下一个事件。条目边界、对齐填充都在
/// 同一处消费，不需要借位或视图偏移修正。
/// </summary>
public sealed class CpioReader
{
    public const string TrailerName = "TRAILER!!!";
    public const int MaxNameLength = 4096;

    private const int OdcHeaderLength = 76;
    private const int NewcHeaderLength = 110;

    private enum State
    {
        Header,
        Name,
        Data,
        Pad,
        Done,
    }

    private byte[] _buffer = new byte[1024];
    private int _start;
    private int _count;

    private CpioFormat? _format;
    private State _state = State.Header;
    private long _nameLength;
    private long _dataLeft;
    private byte[]? _headerBytes;
    private int _padLeft;

    /// <summary>追加一段输入。</summary>
    public void Feed(ReadOnlySpan<byte> input) => Write(input);

    /// <summary>追加一段输入（与 <see cref="Feed(ReadOnlySpan{byte})"/> 等价）。</summary>
    public void Feed(ReadOnlyMemory<byte> input) => Write(input.Span);

    public bool IsComplete => _state == State.Done;

    /// <summary>是否正好在条目边界（可以安全结束）。</summary>
    public bool AtBoundary => _state == State.Header && _count == 0;

    /// <summary>拉取下一个事件；缓冲不足以解析时返回 <c>null</c>，需要继续 <see cref="Feed"/>。</summary>
    public CpioEvent? Pull()
    {
        while (true)
        {
            switch (_state)
            {
                case State.Done:
                    return null;

                case State.Header:
                {
                    if (_format is null)
                    {
                        if (_count < 6)
                        {
                            return null;
                        }

                        // 只认格式，不消费；头部在下面按完整长度读取。
                        AdoptFormat();
                        continue;
                    }

                    var need = (_format == CpioFormat.Newc ? NewcHeaderLength : OdcHeaderLength);
                    if (_count < need)
                    {
                        return null;
                    }

                    _headerBytes = Peek(need).ToArray();
                    var header = _headerBytes.AsSpan();
                    // 名字区：odc 的 namesize 含结尾 NUL；newc 的 namesize 不含，需 +1 并补到 4 字节。
                    var namesize = _format == CpioFormat.Odc
                        ? (long)ReadOctal(header, 59, 6)
                        : (long)ReadHex(header, 94, 8);
                    if (namesize is <= 0 or > MaxNameLength)
                    {
                        throw new InvalidDataException("CPIO 条目名长度非法");
                    }

                    // odc 的 namesize 已含 NUL 且不对齐；newc 的 namesize 也含 NUL，名字区按 "头部+名字" 整体 4 字节对齐。
                    _nameLength = _format == CpioFormat.Odc
                        ? namesize
                        : Align4(NewcHeaderLength + (int)namesize) - NewcHeaderLength;
                    if (_nameLength > MaxNameLength + 4)
                    {
                        throw new InvalidDataException("CPIO 条目名长度非法");
                    }

                    // 头部已解析完，移出缓冲；名字区从此刻的缓冲起点开始，Header 与 Name 状态取得一致。
                    Consume(need);
                    _state = State.Name;
                    continue;
                }

                case State.Name:
                {
                    if (_count < _nameLength)
                    {
                        return null;
                    }

                    var nameBytes = Peek((int)_nameLength);
                    var nul = nameBytes.IndexOf((byte)0);
                    var name = Encoding.UTF8.GetString(nameBytes[..(nul >= 0 ? nul : nameBytes.Length)]);
                    Consume((int)_nameLength);

                    var entry = BuildEntry(_headerBytes, name);
                    _padLeft = 0;
                    if (entry.Name == TrailerName)
                    {
                        _state = State.Done;
                        return new ArchiveComplete();
                    }

                    _dataLeft = entry.Size;
                    // newc 要求条目数据按 4 字节对齐（odc 不需要）。数据由调用方逐段拉取，填充在结束时消费。
                    _padLeft = _format == CpioFormat.Newc ? Align4((int)entry.Size) - (int)entry.Size : 0;
                    _state = entry.Size == 0 ? State.Pad : State.Data;

                    return new EntryStarted(entry);
                }

                case State.Data:
                {
                    if (_count == 0)
                    {
                        return null;
                    }

                    var n = (int)Math.Min(_count, _dataLeft);
                    var data = Peek(n).ToArray();
                    Consume(n);
                    _dataLeft -= n;
                    if (_dataLeft == 0)
                    {
                        _state = State.Pad;
                    }

                    return new EntryData(data);
                }

                case State.Pad:
                {
                    // Pad 只消费 newc 的数据对齐，不产生事件；对齐完就回到 Header 继续拉取。
                    if (_padLeft > 0)
                    {
                        if (_count == 0)
                        {
                            return null;
                        }

                        var n = Math.Min(_count, _padLeft);
                        Consume(n);
                        _padLeft -= n;
                        if (_padLeft > 0)
                        {
                            return null;
                        }
                    }

                    _state = State.Header;
                    return new EntryEnded();
                }
            }

            throw new InvalidOperationException();
        }
    }

    /// <summary>
    /// 便捷驱动：持续从 <paramref name="input"/> 喂入并拉取事件，
    /// 每得到一个事件就通过 <paramref name="onEvent"/> 返回给调用方。
    /// </summary>
    public IEnumerable<CpioEvent> Read(ReadOnlyMemory<byte> input, int chunk = 64 * 1024)
    {
        var pos = 0;
        while (pos < input.Length)
        {
            var take = Math.Min(chunk, input.Length - pos);
            Feed(input.Slice(pos, take).Span);
            pos += take;
            while (Pull() is { } e)
            {
                yield return e;
                if (e is ArchiveComplete)
                {
                    yield break;
                }
            }
        }

        // 处理已经缓存的完整事件。
        while (Pull() is { } e)
        {
            yield return e;
            if (e is ArchiveComplete)
            {
                yield break;
            }
        }
    }

    private void AdoptFormat()
    {
        var magic = Encoding.ASCII.GetString(_buffer, _start, 6);
        _format = magic switch
        {
            "070707" => CpioFormat.Odc,
            "070701" or "070702" => CpioFormat.Newc,
            _ => throw new InvalidDataException($"不认识的 CPIO 魔数 {magic}"),
        };
    }

    private CpioEntry BuildEntry(ReadOnlySpan<byte> header, string name)
    {
        int mode;
        long size;
        uint nlink;
        uint ino;
        if (_format == CpioFormat.Odc)
        {
            // odc 布局（6 位八进制；mtime / filesize 为 11 位）：
            // dev ino mode uid gid nlink rdev mtime namesize filesize。
            ino = ReadOctal(header, 6, 6);
            mode = (int)ReadOctal(header, 18, 6);
            nlink = ReadOctal(header, 36, 6);
            size = (long)ReadOctal(header, 65, 11);
        }
        else
        {
            // newc 布局（13 个 8 位十六进制字段）：magic ino mode uid gid nlink mtime filesize ...
            ino = ReadHex(header, 6, 8);
            mode = (int)ReadHex(header, 14, 8);
            nlink = ReadHex(header, 38, 8);
            size = ReadHex(header, 54, 8);
        }

        var kind = (mode & 0xF000) switch
        {
            0x8000 => CpioKind.Regular,
            0x4000 => CpioKind.Directory,
            _ => CpioKind.Other,
        };
        return new CpioEntry(name, kind, mode, size, nlink, ino);
    }

    internal static int Align4(int n) => (n + 3) & ~3;

    // ---------------------------------------------------------------- 缓冲管理
    //
    // 缓冲始终保持"未解析字节从 _start 开始、共 _count 字节"这一简单不变量：
    // 写入追加在 _start + _count，消费只移动 _start；当缓冲不够时整体搬移到 0 或扩容。
    // 不使用任何视图偏移修正，避免重叠拷贝的边界问题。

    private ReadOnlySpan<byte> Peek(int n) => _buffer.AsSpan(_start, n);

    private void Consume(int n)
    {
        var remaining = _count - n;
        if (n < 0 || remaining < 0) throw new InvalidOperationException($"Consume 越界 n={n} count={_count} start={_start}");
        if (remaining <= 0)
        {
            _start = 0;
            _count = 0;
            return;
        }

        _start += n;
        _count = remaining;
    }

    private void Write(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0)
        {
            return;
        }

        // 先尽量在不搬移的前提下腾出空间。
        if (_start + _count + input.Length > _buffer.Length)
        {
            if (_count + input.Length <= _buffer.Length)
            {
                Buffer.BlockCopy(_buffer, _start, _buffer, 0, _count);
                _start = 0;
            }
            else
            {
                var grown = new byte[Math.Max(_count + input.Length, _buffer.Length * 2)];
                Buffer.BlockCopy(_buffer, _start, grown, 0, _count);
                _buffer = grown;
                _start = 0;
            }
        }

        input.CopyTo(_buffer.AsSpan(_start + _count));
        _count += input.Length;
    }

    // ---------------------------------------------------------------- 字段

    private static uint ReadOctal(ReadOnlySpan<byte> s, int offset, int len)
    {
        uint v = 0;
        for (var i = offset; i < offset + len; i++)
        {
            var c = s[i];
            if (c is < (byte)'0' or > (byte)'7')
            {
                throw new InvalidDataException("CPIO odc 字段不是八进制");
            }

            v = (v * 8) + (uint)(c - '0');
        }

        return v;
    }

    private static uint ReadHex(ReadOnlySpan<byte> s, int offset, int len)
    {
        uint v = 0;
        for (var i = offset; i < offset + len; i++)
        {
            var c = s[i];
            if (c is >= (byte)'0' and <= (byte)'9')
            {
                v = (v * 16) + (uint)(c - '0');
            }
            else if (c is >= (byte)'a' and <= (byte)'f')
            {
                v = (v * 16) + (uint)(c - 'a' + 10);
            }
            else if (c is >= (byte)'A' and <= (byte)'F')
            {
                v = (v * 16) + (uint)(c - 'A' + 10);
            }
            else
            {
                throw new InvalidDataException("CPIO newc 字段不是十六进制");
            }
        }

        return v;
    }
}

/// <summary>把文件写进 odc（070707）格式的 CPIO 归档；AirDrop 发送端只发这种（UP-2）。</summary>
public sealed class OdcWriter
{
    /// <summary>单个条目能表达的最大字节数（11 位八进制 77777777777 = 8589934591）。</summary>
    public const long MaxEntrySize = 8589934591;

    private uint _nextInode = 1;

    public static byte[] RootHeader(long mtime, uint inode = 1) =>
        Header(".", 16877, 0, mtime, inode, 2);

    public static byte[] DirectoryHeader(string name, long mtime, uint inode) =>
        Header(name, 16877, 0, mtime, inode, 2);

    /// <summary>普通文件 0644 的条目头，数据紧跟在头之后、不做对齐（odc 无需填充）。</summary>
    public byte[] FileHeader(string name, long size, long mtime)
    {
        if (size > MaxEntrySize)
        {
            throw new InvalidOperationException("文件超过 odc 单个条目上限");
        }

        return Header(name, 33188, size, mtime, _nextInode++, 1);
    }

    public static byte[] TrailerHeader() => Header(CpioReader.TrailerName, 0, 0, 0, 0, 0);

    private static byte[] Header(string name, int mode, long size, long mtime, uint inode, uint nlink)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var header = string.Concat(
            "070707",
            "000000", // dev
            Convert.ToString(inode & 0x3FFFFF, 8).PadLeft(6, '0'),
            Convert.ToString(mode, 8).PadLeft(6, '0'),
            "000000", // uid
            "000000", // gid
            Convert.ToString(nlink, 8).PadLeft(6, '0'),
            "000000", // rdev
            Convert.ToString(mtime & 0x1FFFFFFF, 8).PadLeft(11, '0'),
            Convert.ToString(nameBytes.Length + 1, 8).PadLeft(6, (char)48),
            Convert.ToString(size, 8).PadLeft(11, '0'));
        var result = new byte[header.Length + nameBytes.Length + 1];
        Encoding.ASCII.GetBytes(header).CopyTo(result, 0);
        nameBytes.CopyTo(result, header.Length);
        return result;
    }
}
