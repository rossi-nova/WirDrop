using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace WirDrop.Core.Mdns;

public enum DnsRecordType : ushort
{
    A = 1,
    Ptr = 12,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Any = 255,
}

public sealed record DnsQuestion(string Name, DnsRecordType Type, bool UnicastResponse = false);

public sealed record DnsRecord(
    string Name,
    DnsRecordType Type,
    uint Ttl,
    byte[] Data,
    bool CacheFlush = false,
    string? Target = null,
    IPAddress? Address = null,
    ushort Priority = 0,
    ushort Weight = 0,
    ushort Port = 0,
    IReadOnlyList<string>? Texts = null)
{
    public static DnsRecord Ptr(string name, string target, uint ttl) =>
        new(name, DnsRecordType.Ptr, ttl, DnsCodec.EncodeName(target), Target: target);

    public static DnsRecord Srv(string name, ushort port, string target, uint ttl) =>
        new(name, DnsRecordType.Srv, ttl, DnsCodec.EncodeSrv(0, 0, port, target), Target: target, Port: port);

    public static DnsRecord Txt(string name, params string[] texts) =>
        new(name, DnsRecordType.Txt, 4500, DnsCodec.EncodeTxt(texts), Texts: texts);

    public static DnsRecord Aaaa(string name, IPAddress address, uint ttl = 120) =>
        new(name, DnsRecordType.Aaaa, ttl, address.GetAddressBytes(), Address: address);

    public static DnsRecord A(string name, IPAddress address, uint ttl = 120) =>
        new(name, DnsRecordType.A, ttl, address.GetAddressBytes(), Address: address);
}

public sealed record DnsMessage(
    ushort Id,
    bool IsResponse,
    IReadOnlyList<DnsQuestion> Questions,
    IReadOnlyList<DnsRecord> Answers,
    IReadOnlyList<DnsRecord> Authorities,
    IReadOnlyList<DnsRecord> Additionals)
{
    public static DnsMessage Query(string name, DnsRecordType type, bool unicast = false, ushort id = 0) =>
        new(id, false, [new DnsQuestion(name, type, unicast)], [], [], []);
}

/// <summary>
/// DNS 报文编解码（RFC 1035 子集），支持 mDNS 依赖的名字压缩、PTR/SRV/TXT/A/AAAA。
/// 只用于受控网段内的发现报文，仍对长度与压缩环做防护。
/// </summary>
public static class DnsCodec
{
    public const int MaxMessage = 9000;

    public static byte[] Encode(DnsMessage message)
    {
        var output = new MemoryStream();
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, message.Id);
        var flags = message.IsResponse ? 0x8400 : 0;
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], (ushort)flags);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], (ushort)message.Questions.Count);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..], (ushort)message.Answers.Count);
        BinaryPrimitives.WriteUInt16BigEndian(header[8..], (ushort)message.Authorities.Count);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], (ushort)message.Additionals.Count);
        output.Write(header);
        foreach (var q in message.Questions)
        {
            WriteName(output, q.Name);
            Span<byte> t = stackalloc byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(t, (ushort)q.Type);
            BinaryPrimitives.WriteUInt16BigEndian(t[2..], (ushort)(q.UnicastResponse ? 0x8001 : 0x0001));
            output.Write(t);
        }

        foreach (var record in message.Answers.Concat(message.Authorities).Concat(message.Additionals))
        {
            WriteRecord(output, record);
        }

        return output.ToArray();
    }

    public static DnsMessage Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12)
        {
            throw new FormatException("DNS 报文过短");
        }

        var id = BinaryPrimitives.ReadUInt16BigEndian(data);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if ((flags & 0x7800) != 0)
        {
            throw new FormatException("不支持的 DNS OPCODE");
        }

        var qd = BinaryPrimitives.ReadUInt16BigEndian(data[4..]);
        var an = BinaryPrimitives.ReadUInt16BigEndian(data[6..]);
        var ns = BinaryPrimitives.ReadUInt16BigEndian(data[8..]);
        var ar = BinaryPrimitives.ReadUInt16BigEndian(data[10..]);
        var total = qd + an + ns + ar;
        if (total > 256)
        {
            throw new FormatException("DNS 记录数过多");
        }

        var pos = 12;
        var questions = new List<DnsQuestion>(qd);
        for (var i = 0; i < qd; i++)
        {
            var name = ReadName(data, ref pos);
            if (pos + 4 > data.Length)
            {
                throw new FormatException("DNS 问题截断");
            }

            var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            var cls = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
            pos += 4;
            questions.Add(new DnsQuestion(name, type, (cls & 0x8000) != 0));
        }

        var answers = ReadRecords(data, ref pos, an);
        var authorities = ReadRecords(data, ref pos, ns);
        var additionals = ReadRecords(data, ref pos, ar);
        return new DnsMessage(id, (flags & 0x8000) != 0, questions, answers, authorities, additionals);
    }

    private static List<DnsRecord> ReadRecords(ReadOnlySpan<byte> data, ref int pos, int count)
    {
        var records = new List<DnsRecord>(count);
        for (var i = 0; i < count; i++)
        {
            var name = ReadName(data, ref pos);
            if (pos + 10 > data.Length)
            {
                throw new FormatException("DNS 记录头截断");
            }

            var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            var cls = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(data[(pos + 4)..]);
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 8)..]);
            pos += 10;
            if (pos + rdLength > data.Length)
            {
                throw new FormatException("DNS 记录数据截断");
            }

            var rdata = data.Slice(pos, rdLength);
            pos += rdLength;
            var flush = (cls & 0x8000) != 0;
            records.Add(type switch
            {
                DnsRecordType.Ptr => new DnsRecord(name, type, ttl, rdata.ToArray(), flush,
                    Target: ReadNameAt(data, pos - rdLength)),
                DnsRecordType.Srv when rdLength >= 7 => new DnsRecord(name, type, ttl, rdata.ToArray(), flush,
                    Priority: BinaryPrimitives.ReadUInt16BigEndian(rdata),
                    Weight: BinaryPrimitives.ReadUInt16BigEndian(rdata[2..]),
                    Port: BinaryPrimitives.ReadUInt16BigEndian(rdata[4..]),
                    Target: ReadNameAt(data, pos - rdLength + 6)),
                DnsRecordType.Txt => new DnsRecord(name, type, ttl, rdata.ToArray(), flush, Texts: ParseTxt(rdata)),
                DnsRecordType.Aaaa when rdLength == 16 => new DnsRecord(name, type, ttl, rdata.ToArray(), flush,
                    Address: new IPAddress(rdata)),
                DnsRecordType.A when rdLength == 4 => new DnsRecord(name, type, ttl, rdata.ToArray(), flush,
                    Address: new IPAddress(rdata)),
                _ => new DnsRecord(name, type, ttl, rdata.ToArray(), flush),
            });
        }

        return records;
    }

    private static string ReadNameAt(ReadOnlySpan<byte> data, int offset)
    {
        var pos = offset;
        return ReadName(data, ref pos);
    }

    public static string ReadName(ReadOnlySpan<byte> data, ref int pos)
    {
        var labels = new List<string>();
        var jumps = 0;
        var cursor = pos;
        var advanced = false;
        while (true)
        {
            if (cursor >= data.Length)
            {
                throw new FormatException("DNS 名字越界");
            }

            var len = data[cursor];
            if (len == 0)
            {
                cursor++;
                if (!advanced)
                {
                    pos = cursor;
                }

                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= data.Length)
                {
                    throw new FormatException("DNS 压缩指针越界");
                }

                var pointer = ((len & 0x3F) << 8) | data[cursor + 1];
                if (!advanced)
                {
                    pos = cursor + 2;
                }

                advanced = true;
                if (++jumps > 32 || pointer >= cursor)
                {
                    throw new FormatException("DNS 压缩指针非法");
                }

                cursor = pointer;
                continue;
            }

            if (cursor + 1 + len > data.Length || len > 63)
            {
                throw new FormatException("DNS 标签越界");
            }

            labels.Add(Encoding.ASCII.GetString(data.Slice(cursor + 1, len)));
            cursor += 1 + len;
            if (!advanced)
            {
                pos = cursor;
            }
        }

        return string.Join('.', labels);
    }

    public static byte[] EncodeName(string name)
    {
        var output = new MemoryStream();
        WriteName(output, name);
        return output.ToArray();
    }

    private static void WriteName(Stream output, string name)
    {
        var trimmed = name.TrimEnd('.');
        if (trimmed.Length > 0)
        {
            foreach (var label in trimmed.Split('.'))
            {
                var bytes = Encoding.ASCII.GetBytes(label);
                if (bytes.Length is 0 or > 63)
                {
                    throw new FormatException("DNS 标签长度非法");
                }

                output.WriteByte((byte)bytes.Length);
                output.Write(bytes);
            }
        }

        output.WriteByte(0);
    }

    public static byte[] EncodeSrv(ushort priority, ushort weight, ushort port, string target)
    {
        using var ms = new MemoryStream();
        Span<byte> head = stackalloc byte[6];
        BinaryPrimitives.WriteUInt16BigEndian(head, priority);
        BinaryPrimitives.WriteUInt16BigEndian(head[2..], weight);
        BinaryPrimitives.WriteUInt16BigEndian(head[4..], port);
        ms.Write(head);
        WriteName(ms, target);
        return ms.ToArray();
    }

    public static byte[] EncodeTxt(IReadOnlyList<string> texts)
    {
        using var ms = new MemoryStream();
        if (texts.Count == 0)
        {
            ms.WriteByte(0);
            return ms.ToArray();
        }

        foreach (var text in texts)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            if (bytes.Length > 255)
            {
                throw new FormatException("TXT 条目过长");
            }

            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes);
        }

        return ms.ToArray();
    }

    private static List<string> ParseTxt(ReadOnlySpan<byte> rdata)
    {
        var texts = new List<string>();
        var pos = 0;
        while (pos < rdata.Length)
        {
            var len = rdata[pos++];
            if (pos + len > rdata.Length)
            {
                throw new FormatException("TXT 截断");
            }

            texts.Add(Encoding.UTF8.GetString(rdata.Slice(pos, len)));
            pos += len;
        }

        return texts;
    }

    private static void WriteRecord(Stream output, DnsRecord record)
    {
        WriteName(output, record.Name);
        Span<byte> head = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(head, (ushort)record.Type);
        BinaryPrimitives.WriteUInt16BigEndian(head[2..], (ushort)(record.CacheFlush ? 0x8001 : 0x0001));
        BinaryPrimitives.WriteUInt32BigEndian(head[4..], record.Ttl);
        BinaryPrimitives.WriteUInt16BigEndian(head[8..], (ushort)record.Data.Length);
        output.Write(head);
        output.Write(record.Data);
    }

    /// <summary>名字比较忽略大小写与末尾点（RFC 6762 §16）。</summary>
    public static bool NameEquals(string a, string b) =>
        string.Equals(a.TrimEnd('.'), b.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
}
