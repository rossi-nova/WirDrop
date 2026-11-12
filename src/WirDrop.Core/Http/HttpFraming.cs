using System.Text;

namespace WirDrop.Core.Http;

public enum BodyKind
{
    None,
    ContentLength,
    Chunked,
}

/// <summary>解析后的请求头。头名与头值均已规范化。</summary>
public sealed class HttpRequestHead
{
    public required string Method { get; init; }

    public required string Target { get; init; }

    public required IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; }

    public required BodyKind BodyKind { get; init; }

    public long ContentLength { get; init; }

    public bool ExpectContinue { get; init; }

    public string? Header(string name) => HttpFraming.GetHeader(Headers, name);

    public int HeaderCount(string name) => HttpFraming.CountHeader(Headers, name);
}

public sealed class HttpFramingException(string message, int statusCode) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}

public sealed class HttpParserOptions
{
    public int MaxHeadBytes { get; init; } = 16 * 1024;

    public int MaxHeaderCount { get; init; } = 64;

    public int MaxBodyBytes { get; init; } = 64 * 1024 * 1024;
}

/// <summary>
/// HTTP/1.1 严格分帧（SEC-7）：拒绝有歧义的 Content-Length / Transfer-Encoding 组合、
/// 裸 CR/LF、过大的头部；请求体支持 Content-Length 与 chunked 两种。
/// </summary>
public static class HttpFraming
{
    /// <summary>从流中读取一个请求头；连接在头之前结束返回 null。</summary>
    public static HttpRequestHead? ReadRequestHead(Stream stream, HttpParserOptions? options = null, CancellationToken ct = default)
    {
        options ??= new HttpParserOptions();
        var buffer = new MemoryStream();
        var one = new byte[1];
        var state = 0; // 依次匹配 \r \n \r \n
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var n = stream.Read(one, 0, 1);
            if (n == 0)
            {
                if (buffer.Length == 0)
                {
                    return null;
                }

                throw new HttpFramingException("HTTP 头部不完整", 400);
            }

            buffer.WriteByte(one[0]);
            if (buffer.Length > options.MaxHeadBytes)
            {
                throw new HttpFramingException("HTTP 头部过大", 431);
            }

            state = one[0] switch
            {
                (byte)'\r' when state is 0 or 2 => state + 1,
                (byte)'\n' when state is 1 or 3 => state + 1,
                _ => 0,
            };
            if (state == 4)
            {
                break;
            }
        }

        var head = ParseRequestHead(buffer.ToArray(), options);
        return head;
    }

    public static HttpRequestHead ParseRequestHead(byte[] bytes, HttpParserOptions? options = null)
    {
        options ??= new HttpParserOptions();
        var text = Encoding.ASCII.GetString(bytes);
        // 去掉结尾的空行。
        text = text.EndsWith("\r\n\r\n", StringComparison.Ordinal) ? text[..^4] : text;
        var lines = text.Split("\r\n");
        if (lines.Length == 0)
        {
            throw new HttpFramingException("缺少请求行", 400);
        }

        var parts = lines[0].Split(' ');
        if (parts.Length != 3 || parts[0].Length == 0 || !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
        {
            throw new HttpFramingException("请求行非法", 400);
        }

        var headers = new List<KeyValuePair<string, string>>();
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] is ' ' or '\t')
            {
                throw new HttpFramingException("拒绝折行续写", 400);
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                throw new HttpFramingException("头部缺少冒号", 400);
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (!name.All(IsTokenChar))
            {
                throw new HttpFramingException("头部名非法", 400);
            }

            headers.Add(new KeyValuePair<string, string>(name, value));
        }

        if (headers.Count > options.MaxHeaderCount)
        {
            throw new HttpFramingException("头部过多", 431);
        }

        var contentLengths = headers.Where(h => h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).ToList();
        var transferEncoding = headers.Where(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).ToList();
        BodyKind kind;
        long length = 0;
        if (contentLengths.Count > 0 && transferEncoding.Count > 0)
        {
            throw new HttpFramingException("Content-Length 与 Transfer-Encoding 冲突", 400);
        }

        if (contentLengths.Count > 1)
        {
            // 多个 Content-Length 必须完全一致，且值相同。
            if (contentLengths.Select(h => h.Value).Distinct(StringComparer.Ordinal).Count() != 1)
            {
                throw new HttpFramingException("Content-Length 重复且不一致", 400);
            }
        }

        if (contentLengths.Count > 0)
        {
            var raw = contentLengths[0].Value;
            if (raw.Length == 0 || raw.Length > 19 || !raw.All(char.IsAsciiDigit))
            {
                throw new HttpFramingException("Content-Length 非法", 400);
            }

            length = long.Parse(raw);
            if (length > options.MaxBodyBytes)
            {
                throw new HttpFramingException("请求体过大", 413);
            }

            kind = length == 0 ? BodyKind.None : BodyKind.ContentLength;
        }
        else if (transferEncoding.Count > 0)
        {
            if (transferEncoding.Count > 1
                || !transferEncoding[0].Value.Equals("chunked", StringComparison.OrdinalIgnoreCase))
            {
                throw new HttpFramingException("不支持的 Transfer-Encoding", 400);
            }

            kind = BodyKind.Chunked;
        }
        else
        {
            kind = BodyKind.None;
        }

        var expect = headers.Any(h =>
            h.Key.Equals("Expect", StringComparison.OrdinalIgnoreCase)
            && h.Value.Equals("100-continue", StringComparison.OrdinalIgnoreCase));

        return new HttpRequestHead
        {
            Method = parts[0],
            Target = parts[1],
            Headers = headers,
            BodyKind = kind,
            ContentLength = length,
            ExpectContinue = expect,
        };
    }

    /// <summary>
    /// 按 <paramref name="head"/> 的声明读取请求体。返回只读的请求体（已在 <paramref name="options"/> 上限内）。
    /// chunked 体也会严格校验块大小与结尾。
    /// </summary>
    public static byte[] ReadBody(Stream stream, HttpRequestHead head, HttpParserOptions? options = null, CancellationToken ct = default)
    {
        options ??= new HttpParserOptions();
        return head.BodyKind switch
        {
            BodyKind.None => [],
            BodyKind.ContentLength => ReadExactly(stream, checked((int)head.ContentLength), ct),
            BodyKind.Chunked => ReadChunked(stream, options, ct),
            _ => throw new HttpFramingException("未知的请求体类型", 400),
        };
    }

    private static byte[] ReadExactly(Stream stream, int length, CancellationToken ct)
    {
        var buffer = new byte[length];
        var read = 0;
        while (read < length)
        {
            ct.ThrowIfCancellationRequested();
            var n = stream.Read(buffer, read, length - read);
            if (n == 0)
            {
                throw new HttpFramingException("请求体提前结束", 400);
            }

            read += n;
        }

        return buffer;
    }

    private static byte[] ReadChunked(Stream stream, HttpParserOptions options, CancellationToken ct)
    {
        using var output = new MemoryStream();
        while (true)
        {
            var line = ReadLine(stream, 1024, ct);
            var semi = line.IndexOf(';');
            var sizeText = (semi >= 0 ? line[..semi] : line).Trim();
            if (sizeText.Length is 0 or > 16 || !sizeText.All(char.IsAsciiHexDigit))
            {
                throw new HttpFramingException("chunk 长度非法", 400);
            }

            var size = long.Parse(sizeText, System.Globalization.NumberStyles.HexNumber);
            if (size == 0)
            {
                // 读取 trailer，直到空行。
                while (true)
                {
                    var trailer = ReadLine(stream, options.MaxHeadBytes, ct);
                    if (trailer.Length == 0)
                    {
                        return output.ToArray();
                    }
                }
            }

            if (output.Length + size > options.MaxBodyBytes)
            {
                throw new HttpFramingException("请求体过大", 413);
            }

            var chunk = ReadExactly(stream, checked((int)size), ct);
            output.Write(chunk);
            var crlf = ReadExactly(stream, 2, ct);
            if (crlf[0] != '\r' || crlf[1] != '\n')
            {
                throw new HttpFramingException("chunk 后缺少 CRLF", 400);
            }
        }
    }

    private static string ReadLine(Stream stream, int maxLength, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var prev = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var b = stream.ReadByte();
            if (b < 0)
            {
                throw new HttpFramingException("块行提前结束", 400);
            }

            if (prev == '\r' && b == '\n')
            {
                sb.Length--;
                return sb.ToString();
            }

            if (sb.Length >= maxLength)
            {
                throw new HttpFramingException("块行过长", 400);
            }

            sb.Append((char)b);
            prev = b;
        }
    }

    public static string? GetHeader(IReadOnlyList<KeyValuePair<string, string>> headers, string name)
    {
        string? found = null;
        foreach (var h in headers)
        {
            if (!h.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (found is not null)
            {
                return null;
            }

            found = h.Value;
        }

        return found;
    }

    public static int CountHeader(IReadOnlyList<KeyValuePair<string, string>> headers, string name) =>
        headers.Count(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static bool IsTokenChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c);

    /// <summary>写出一个带 Content-Length 的响应。</summary>
    public static void WriteResponse(Stream stream, int status, byte[] body, params (string Name, string Value)[] headers)
    {
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 ").Append(status).Append(' ').Append(ReasonPhrase(status)).Append("\r\n");
        foreach (var (name, value) in headers)
        {
            sb.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        sb.Append("Content-Length: ").Append(body.Length).Append("\r\n\r\n");
        var head = Encoding.ASCII.GetBytes(sb.ToString());
        stream.Write(head);
        stream.Write(body);
        stream.Flush();
    }

    public static string ReasonPhrase(int status) => status switch
    {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        406 => "Not Acceptable",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
}
