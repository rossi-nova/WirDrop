using System.Text;

namespace WirDrop.Core.Security;

/// <summary>一条经过校验的相对路径：若干组件，每个组件都是本平台可安全创建的名字。</summary>
public sealed class SafeRelativePath
{
    public const int MaxComponent = 255;
    public const int MaxPath = 1024;

    private readonly string[] _components;

    private SafeRelativePath(string[] components) => _components = components;

    public IReadOnlyList<string> Components => _components;

    public string Name => _components[^1];

    public SafeRelativePath? Parent => _components.Length > 1 ? new SafeRelativePath(_components[..^1]) : null;

    public override string ToString() => string.Join('/', _components);

    /// <summary>校验归档条目名或 FileBomPath：允许 <c>./a/b</c> 或 <c>a/b</c>。</summary>
    public static SafeRelativePath Parse(string path)
    {
        var rest = path.StartsWith("./", StringComparison.Ordinal) ? path[2..] : path;
        if (rest.Length == 0 || path.Length > MaxPath)
        {
            throw new UnsafePathException(path);
        }

        var components = rest.Split('/');
        if (components.Any(c => !IsSafeComponent(c)))
        {
            throw new UnsafePathException(path);
        }

        return new SafeRelativePath(components);
    }

    /// <summary>校验单个文件名（FileName）。</summary>
    public static SafeRelativePath FileName(string name)
    {
        if (!IsSafeComponent(name) || name.Length > MaxPath)
        {
            throw new UnsafePathException(name);
        }

        return new SafeRelativePath([name]);
    }

    public bool StartsWith(SafeRelativePath prefix) =>
        _components.Length >= prefix._components.Length
        && _components.Take(prefix._components.Length).SequenceEqual(prefix._components, StringComparer.Ordinal);

    public bool Equals(SafeRelativePath other) =>
        _components.SequenceEqual(other._components, StringComparer.Ordinal);

    public static bool IsSafeComponent(string c)
    {
        if (string.IsNullOrEmpty(c) || c == "." || c == ".." || c.Length > MaxComponent)
        {
            return false;
        }

        foreach (var ch in c)
        {
            if (ch is '/' or '\\' || char.IsControl(ch) || IsBidiControl(ch))
            {
                return false;
            }
        }

        return WindowsName.IsCreatable(c);
    }

    /// <summary>双向文本控制符可能让文件名伪装成另一个（SEC-1）。</summary>
    private static bool IsBidiControl(char ch) => ch is >= '‪' and <= '‮' or >= '⁦' and <= '⁩';
}

public sealed class UnsafePathException(string path) : Exception($"不安全的路径：{path}");

/// <summary>Windows 文件名规则：保留名、非法字符、结尾点或空格都被拒绝。</summary>
public static class WindowsName
{
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static bool IsCreatable(string name)
    {
        if (name.EndsWith('.') || name.EndsWith(' '))
        {
            return false;
        }

        if (name.IndexOfAny(['<', '>', ':', '"', '|', '?', '*']) >= 0)
        {
            return false;
        }

        var stem = name.Split('.')[0].TrimEnd(' ');
        return !Reserved.Contains(stem);
    }

    /// <summary>为重名文件生成不覆盖的名称：<c>name (1).ext</c>。</summary>
    public static string UniqueIn(string directory, string name)
    {
        var target = Path.Combine(directory, name);
        if (!File.Exists(target) && !Directory.Exists(target))
        {
            return name;
        }

        var stem = Path.GetFileNameWithoutExtension(name);
        var ext = Path.GetExtension(name);
        for (var i = 1; i < 10000; i++)
        {
            var candidate = $"{stem} ({i}){ext}";
            if (!File.Exists(Path.Combine(directory, candidate)) && !Directory.Exists(Path.Combine(directory, candidate)))
            {
                return candidate;
            }
        }

        return $"{stem}-{Guid.NewGuid():N}{ext}";
    }

    /// <summary>把任意字符串变成当前文件系统接受的文件名，供 /Ask 回显与本地落地共用。</summary>
    public static string Sanitize(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "file";
        }

        var sb = new StringBuilder(name.Length);
        foreach (var ch in name)
        {
            sb.Append(ch is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*' || char.IsControl(ch) ? '_' : ch);
        }

        var s = sb.ToString().Trim().TrimEnd('.', ' ');
        if (s.Length == 0)
        {
            return "file";
        }

        var stem = s.Split('.')[0].TrimEnd(' ');
        if (Reserved.Contains(stem))
        {
            s = "_" + s;
        }

        return s.Length > 200 ? s[..200] : s;
    }
}