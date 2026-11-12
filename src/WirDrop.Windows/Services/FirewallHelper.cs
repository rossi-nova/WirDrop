using System.Diagnostics;
using System.IO;

namespace WirDrop.Windows;

/// <summary>
/// Windows 防火墙：AirDrop 接收端监听 TCP 8771，若未放行，iPhone/Mac 发起的连接会被直接丢弃，
/// 表现为"设备可见但一发送就失败"。这里探测现有规则并给出可执行提示。
/// </summary>
public static class FirewallHelper
{
    public const int Port = 8771;

    /// <summary>检查入站 8771 是否放行；无需放行时返回 null，否则返回给用户看的提示。</summary>
    public static string? EnsureInboundRule()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            // netsh 检查比 COM 接口稳定，也不需要管理员权限读取。
            var output = Run("netsh", $"advfirewall firewall show rule name=\"WirDrop\" verbose");
            if (output.Contains("允许", StringComparison.Ordinal) || output.Contains("Allow", StringComparison.Ordinal))
            {
                return null;
            }

            var blocked = IsProbablyBlocked();
            return blocked
                ? "提示：Windows 防火墙可能拦截入站 8771 端口。若 iPhone/Mac 看不到本机或发送失败，"
                  + "请以管理员身份运行：netsh advfirewall firewall add rule name=\"WirDrop\" "
                  + $"dir=in action=allow protocol=TCP localport={Port}"
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool IsProbablyBlocked()
    {
        try
        {
            var profiles = Run("netsh", "advfirewall show allprofiles state");
            return profiles.Contains("ON", StringComparison.OrdinalIgnoreCase)
                || profiles.Contains("启用", StringComparison.Ordinal);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string Run(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi) ?? throw new IOException($"无法启动 {exe}");
        var text = p.StandardOutput.ReadToEnd();
        p.WaitForExit(3000);
        return text;
    }
}