using System.Collections;
using System.Globalization;
using System.Text;

namespace WirDrop.Core.Plist;

/// <summary>
/// AirDrop 报文用的二进制属性列表（bplist00）编解码器。
///
/// 解码只接受 <c>bplist00</c>，强制对象表边界与嵌套深度上限（SEC-6）；
/// 共享/循环引用按对象编号缓存，重复解析只会展开一次。
/// 编码输出 Apple 的通用布局：全对象偏移表、定长引用宽度、固定 8 字节尾。
/// </summary>
public static class BinaryPlist
{
    private static readonly byte[] Magic = "bplist00"u8.ToArray();

    /// <summary>尾部固定 32 字节；对象区与偏移表都在它之前。</summary>
    private const int TrailerSize = 32;

    public const int MaxDepth = 64;

    public static bool LooksLikeBinaryPlist(ReadOnlySpan<byte> data) =>
        data.Length >= 8 + TrailerSize && data[..8].SequenceEqual(Magic);

    public static object? Parse(ReadOnlySpan<byte> data, int maxDepth = MaxDepth)
    {
        if (!LooksLikeBinaryPlist(data))
        {
            throw new FormatException("不是二进制属性列表");
        }

        return new Reader(data.ToArray(), maxDepth).ReadTopObject();
    }

    public static byte[] Serialize(object? value) => new Writer().Write(value);

    // ---------------------------------------------------------------- reader

    private sealed class Reader
    {
        private readonly byte[] _buf;
        private readonly int _offsetSize;
        private readonly int _refSize;
        private readonly int _numObjects;
        private readonly int _topObject;
        private readonly int _objectsEnd;
        private readonly int _tableOffset;
        private readonly int _maxDepth;

        public Reader(byte[] buffer, int maxDepth)
        {
            _buf = buffer;
            _maxDepth = maxDepth;
            var trailer = buffer.Length - TrailerSize;
            // 尾部布局：6 字节未用，1 字节偏移宽度，1 字节引用宽度，
            // 8 字节对象数，8 字节顶层对象编号，8 字节偏移表位置。
            var offsetIntSize = buffer[trailer + 6];
            var refSize = buffer[trailer + 7];
            var numObjects = ReadBE64(buffer, trailer + 8);
            var topObject = ReadBE64(buffer, trailer + 16);
            var tableOffset = ReadBE64(buffer, trailer + 24);

            if (offsetIntSize is < 1 or > 8 || refSize is < 1 or > 8)
            {
                throw new FormatException("bplist 引用宽度非法");
            }

            if (numObjects == 0 || numObjects > int.MaxValue || topObject >= numObjects
                || tableOffset < 8 || tableOffset > (ulong)trailer)
            {
                throw new FormatException("bplist 尾部结构非法");
            }

            _offsetSize = offsetIntSize;
            _refSize = refSize;
            _numObjects = (int)numObjects;
            _topObject = (int)topObject;
            _tableOffset = (int)tableOffset;
            _objectsEnd = _tableOffset;
            if (tableOffset + ((ulong)_offsetSize * numObjects) > (ulong)trailer)
            {
                throw new FormatException("bplist 偏移表越界");
            }
        }

        public object? ReadTopObject() => ReadObject(_topObject, 0, new Dictionary<int, object?>());

        private int OffsetOf(int index)
        {
            var pos = _tableOffset + (index * _offsetSize);
            var offset = 0u;
            for (var i = 0; i < _offsetSize; i++)
            {
                offset = (offset << 8) | _buf[pos + i];
            }

            if (offset < 8 || offset >= (uint)_objectsEnd)
            {
                throw new FormatException("bplist 对象偏移非法");
            }

            return (int)offset;
        }

        private object? ReadObject(int index, int depth, Dictionary<int, object?> cache)
        {
            if (depth > _maxDepth)
            {
                throw new FormatException("bplist 嵌套过深");
            }

            if (cache.TryGetValue(index, out var cached))
            {
                return cached;
            }

            var pos = OffsetOf(index);
            var marker = _buf[pos++];
            var type = marker >> 4;
            var info = marker & 0x0F;

            // 集合标记：0xA0 数组、0xC0 集合、0xD0 字典。AirDrop 只用 0xA/0xD，0xC/A 都按容器处理。
            if (type is 0xC or 0xD)
            {
                type = 0xB;
            }

            switch (type)
            {
                case 0x0:
                    return info switch
                    {
                        0x0 => null,
                        0x8 => false,
                        0x9 => true,
                        _ => throw new FormatException($"不支持的 bplist 简单对象 0x{marker:x2}"),
                    };

                case 0x1:
                {
                    var len = 1 << info;
                    if (len > 16)
                    {
                        throw new FormatException("bplist 整数宽度非法");
                    }

                    Need(pos, len);
                    return len switch
                    {
                        // 1/2/4 字节按无符号读，8 字节按有符号读（Apple 只在这里写负数）。
                        1 => (int)_buf[pos],
                        2 => (int)ReadBE(_buf.AsSpan(pos, 2)),
                        4 => (int)ReadBE(_buf.AsSpan(pos, 4)),
                        8 => (long)ReadBE(_buf.AsSpan(pos, 8)),
                        _ => ReadHugeInteger(_buf.AsSpan(pos, len)),
                    };
                }

                case 0x2:
                    switch (info)
                    {
                        case 2:
                            Need(pos, 4);
                            return BitConverter.Int32BitsToSingle((int)ReadBE(_buf.AsSpan(pos, 4)));
                        case 3:
                            Need(pos, 8);
                            return BitConverter.Int64BitsToDouble((long)ReadBE(_buf.AsSpan(pos, 8)));
                        default:
                            throw new FormatException("bplist 实数宽度非法");
                    }

                case 0x3 when info == 3:
                {
                    // 日期：以 2001-01-01 为起点的秒数。
                    Need(pos, 8);
                    var seconds = BitConverter.Int64BitsToDouble((long)ReadBE(_buf.AsSpan(pos, 8)));
                    return DateTime.UnixEpoch.AddTicks((long)((seconds + 978307200.0) * TimeSpan.TicksPerSecond));
                }

                case 0x4:
                {
                    var n = (int)ReadLength(info, ref pos);
                    Need(pos, n);
                    return _buf.AsSpan(pos, n).ToArray();
                }

                case 0x5:
                {
                    var n = (int)ReadLength(info, ref pos);
                    Need(pos, n);
                    return Encoding.ASCII.GetString(_buf, pos, n);
                }

                case 0x6:
                {
                    var n = (int)ReadLength(info, ref pos);
                    Need(pos, n * 2);
                    return Encoding.BigEndianUnicode.GetString(_buf, pos, n * 2);
                }

                case 0x7:
                {
                    var n = (int)ReadLength(info, ref pos);
                    Need(pos, n);
                    return Encoding.UTF8.GetString(_buf, pos, n);
                }

                case 0x8:
                {
                    var n = 1 << info;
                    Need(pos, n);
                    return new Uid(ReadBE(_buf.AsSpan(pos, n)));
                }

                case 0xA:
                {
                    var count = ReadLength(info, ref pos);
                    var refs = ReadRefs(count, ref pos);
                    var list = new List<object?>((int)count);
                    cache[index] = list;
                    foreach (var r in refs)
                    {
                        list.Add(ReadObject(r, depth + 1, cache));
                    }

                    return list;
                }

                case 0xB:
                {
                    var count = ReadLength(info, ref pos);
                    var keyRefs = ReadRefs(count, ref pos);
                    var valueRefs = ReadRefs(count, ref pos);
                    var dict = new Dictionary<string, object?>();
                    cache[index] = dict;
                    for (var i = 0; i < count; i++)
                    {
                        var key = ReadObject(keyRefs[i], depth + 1, cache) as string
                                  ?? throw new FormatException("bplist 字典键不是字符串");
                        dict[key] = ReadObject(valueRefs[i], depth + 1, cache);
                    }

                    return dict;
                }

                default:
                    throw new FormatException($"不支持的 bplist 类型 0x{marker:x2}");
            }
        }

        private long ReadLength(int info, ref int pos)
        {
            if (info != 0xF)
            {
                return info;
            }

            Need(pos, 1);
            var marker = _buf[pos++];
            if ((marker >> 4) != 1)
            {
                throw new FormatException("bplist 长度标记非法");
            }

            var len = 1 << (marker & 0x0F);
            Need(pos, len);
            var value = ReadBE(_buf.AsSpan(pos, len));
            pos += len;
            if (value > (ulong)int.MaxValue)
            {
                throw new FormatException("bplist 长度越界");
            }

            return (long)value;
        }

        private int[] ReadRefs(long count, ref int pos)
        {
            if (count > _buf.Length)
            {
                throw new FormatException("bplist 引用数非法");
            }

            Need(pos, (int)count * _refSize);
            var result = new int[count];
            for (var i = 0; i < count; i++)
            {
                long r = 0;
                for (var b = 0; b < _refSize; b++)
                {
                    r = (r << 8) | _buf[pos++];
                }

                if (r >= _numObjects)
                {
                    throw new FormatException("bplist 对象引用越界");
                }

                result[i] = (int)r;
            }

            return result;
        }

        private void Need(int pos, int len)
        {
            if (pos < 0 || len < 0 || pos + (long)len > _objectsEnd)
            {
                throw new FormatException("bplist 对象越界");
            }
        }

        private static object ReadHugeInteger(ReadOnlySpan<byte> raw)
        {
            // 128 位整数不会出现在 AirDrop 报文里；按符号扩展的 long 兜底。
            var v = ReadBE(raw);
            return raw[0] >= 0x80 ? (long)v : v;
        }
    }

    // ---------------------------------------------------------------- writer

    private sealed class Writer
    {
        // 只对容器做引用去重（防自引用无限展开）；标量按值写入。
        private readonly List<byte[]> _objects = new();
        private readonly Dictionary<object, int> _refs = new(ReferenceEqualityComparer.Instance);

        public byte[] Write(object? value)
        {
            WriteObject(value, 0);
            var width = _objects.Count <= 0xFF ? 1 : _objects.Count <= 0xFFFF ? 2 : 4;

            var ms = new MemoryStream();
            ms.Write(Magic);
            var offsets = new int[_objects.Count];
            for (var i = 0; i < _objects.Count; i++)
            {
                offsets[i] = (int)ms.Position;
                ms.Write(_objects[i]);
            }

            // 偏移量也在 256 以内时 1 字节即可；否则升到 2 字节。
            var offsetSize = offsets[^1] <= 0xFF ? 1 : 2;
            var tableOffset = (int)ms.Position;
            foreach (var off in offsets)
            {
                WriteBE(ms, (ulong)off, offsetSize);
            }

            ms.Write(new byte[6]);
            ms.WriteByte((byte)offsetSize);
            ms.WriteByte((byte)width);
            WriteBE(ms, (ulong)_objects.Count, 8);
            WriteBE(ms, 0, 8);
            WriteBE(ms, (ulong)tableOffset, 8);
            return ms.ToArray();
        }

        private int WriteObject(object? value, int depth)
        {
            if (depth > MaxDepth)
            {
                throw new FormatException("bplist 嵌套过深");
            }

            switch (value)
            {
                case null:
                    return Add([0x00]);
                case bool b:
                    return Add([b ? (byte)0x09 : (byte)0x08]);
                case int i32:
                    return Add(EncodeLong(i32));
                case short i16:
                    return Add(EncodeLong(i16));
                case long i64:
                    return Add(EncodeLong(i64));
                case string s:
                    return Add(EncodeString(s));
                case byte[] data:
                    return Add(Concat(LengthHeader(0x40, data.Length), data));
                case double d:
                {
                    var bytes = new byte[9];
                    bytes[0] = 0x23;
                    WriteBE(bytes.AsSpan(1), (ulong)BitConverter.DoubleToInt64Bits(d), 8);
                    return Add(bytes);
                }
            }

            if (_refs.TryGetValue(value, out var existing))
            {
                return existing;
            }

            var index = _objects.Count;
            _objects.Add([]);
            switch (value)
            {
                case IList list:
                {
                    var refs = new List<int>(list.Count);
                    for (var k = 0; k < list.Count; k++)
                    {
                        refs.Add(WriteObject(list[k], depth + 1));
                    }

                    _objects[index] = Concat(LengthHeader(0xA0, refs.Count), Refs(refs));
                    break;
                }

                case IDictionary<string, object?> typed:
                    _objects[index] = WriteDict(typed.Keys.Cast<object>().ToList(), typed.Values.ToList(), depth);
                    break;

                case IDictionary dict:
                {
                    var keys = new List<object>(dict.Count);
                    var values = new List<object?>(dict.Count);
                    foreach (DictionaryEntry e in dict)
                    {
                        keys.Add(e.Key!);
                        values.Add(e.Value);
                    }

                    _objects[index] = WriteDict(keys, values, depth);
                    break;
                }

                default:
                    throw new NotSupportedException($"bplist 不支持的类型 {value.GetType().Name}");
            }

            _refs[value] = index;
            return index;
        }

        private byte[] WriteDict(List<object> keys, List<object?> values, int depth)
        {
            var keyRefs = new List<int>(keys.Count);
            var valueRefs = new List<int>(keys.Count);
            for (var i = 0; i < keys.Count; i++)
            {
                var key = Convert.ToString(keys[i], CultureInfo.InvariantCulture)!;
                keyRefs.Add(WriteObject(key, depth + 1));
                valueRefs.Add(WriteObject(values[i], depth + 1));
            }

            return Concat(LengthHeader(0xD0, keys.Count), Refs(keyRefs), Refs(valueRefs));
        }

        private int Add(byte[] bytes)
        {
            _objects.Add(bytes);
            return _objects.Count - 1;
        }

        private static byte[] EncodeLong(long v)
        {
            // 非负数按 Apple 的习惯取最短宽度（1/2/4/8 字节），负数一律 8 字节。
            if (v is >= 0 and <= 0xFF)
            {
                return [0x10, (byte)v];
            }

            if (v is >= 0 and <= 0xFFFF)
            {
                return [0x11, (byte)(v >> 8), (byte)v];
            }

            if (v is >= 0 and <= 0xFFFFFFFF)
            {
                return [0x12, (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
            }

            return [0x13,
                (byte)(v >> 56), (byte)(v >> 48), (byte)(v >> 40), (byte)(v >> 32),
                (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
        }

        private static byte[] EncodeString(string s)
        {
            // 纯 ASCII 用 ASCII 串（0x5），否则 UTF-16BE（0x6），与 CFBinaryPList 的习惯一致。
            if (s.All(c => c < 0x80))
            {
                var bytes = new byte[s.Length];
                for (var i = 0; i < s.Length; i++)
                {
                    bytes[i] = (byte)s[i];
                }

                return Concat(LengthHeader(0x50, s.Length), bytes);
            }

            var utf16 = new byte[s.Length * 2];
            for (var i = 0; i < s.Length; i++)
            {
                WriteBE(utf16.AsSpan(i * 2), s[i], 2);
            }

            return Concat(LengthHeader(0x60, s.Length), utf16);
        }

        private static byte[] LengthHeader(int baseMarker, int count)
        {
            if (count < 0xF)
            {
                return [(byte)(baseMarker | count)];
            }

            if (count <= 0xFF)
            {
                return [(byte)(baseMarker | 0xF), 0x10, (byte)count];
            }

            if (count <= 0xFFFF)
            {
                return [(byte)(baseMarker | 0xF), 0x11, (byte)(count >> 8), (byte)count];
            }

            return [(byte)(baseMarker | 0xF), 0x12, (byte)(count >> 24), (byte)(count >> 16), (byte)(count >> 8), (byte)count];
        }

        private static byte[] Refs(List<int> refs)
        {
            var width = refs.Count == 0 || refs.Max() <= 0xFF ? 1 : refs.Max() <= 0xFFFF ? 2 : 4;
            var result = new byte[refs.Count * width];
            for (var i = 0; i < refs.Count; i++)
            {
                WriteBE(result.AsSpan(i * width), (ulong)refs[i], width);
            }

            return result;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var result = new byte[parts.Sum(p => p.Length)];
            var pos = 0;
            foreach (var p in parts)
            {
                p.CopyTo(result, pos);
                pos += p.Length;
            }

            return result;
        }
    }

    // ---------------------------------------------------------------- big-endian helpers

    private static ulong ReadBE(ReadOnlySpan<byte> s)
    {
        ulong v = 0;
        foreach (var b in s)
        {
            v = (v << 8) | b;
        }

        return v;
    }

    private static ulong ReadBE64(byte[] buf, int pos) => ReadBE(buf.AsSpan(pos, 8));

    private static void WriteBE(Span<byte> dst, ulong value, int width)
    {
        for (var i = width - 1; i >= 0; i--)
        {
            dst[i] = (byte)value;
            value >>= 8;
        }
    }

    private static void WriteBE(Stream s, ulong value, int width)
    {
        for (var i = width - 1; i >= 0; i--)
        {
            s.WriteByte((byte)(value >> (i * 8)));
        }
    }
}

/// <summary>bplist 的 UID 对象（NSKeyedArchiver 使用），AirDrop 报文里通常不出现。</summary>
public sealed record Uid(ulong Value);
