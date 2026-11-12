using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WirDrop.Core.Security;

/// <summary>
/// AirDrop 的 TLS 端点：只做加密，不做对端认证（TLS-2）。
///
/// 收发双方都接受自签证书，不校验主机名；接收端提供一张本机自签证书，
/// 发送端在对方要求时可选地出示客户端证书（TLS-3）。TLS 版本限定 1.2 / 1.3（TLS-1）。
/// </summary>
public static class AirDropTls
{
    public const string ServerName = "airdrop.local";

    private static readonly bool[] SkipVerify = [true];

    public static SslServerAuthenticationOptions ServerOptions(X509Certificate2 certificate, bool requestClientCert = true)
    {
        return new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ClientCertificateRequired = false, // 不对客户端证书做强制要求
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
            AllowRenegotiation = false,
            ApplicationProtocols = [],
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
    }

    public static SslClientAuthenticationOptions ClientOptions(X509Certificate2? clientCertificate = null)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = ServerName,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
            ClientCertificates = clientCertificate is null ? null : [clientCertificate],
            AllowRenegotiation = false,
            ApplicationProtocols = [],
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
    }

    /// <summary>连接后把 TLS 流包装成可用流（SslStream 已握手）。</summary>
    public static async Task<SslStream> ConnectAsync(Stream inner, X509Certificate2? clientCertificate, CancellationToken ct = default)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsClientAsync(ClientOptions(clientCertificate), ct).ConfigureAwait(false);
        return ssl;
    }

    public static async Task<SslStream> AcceptAsync(Stream inner, X509Certificate2 certificate, CancellationToken ct = default)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsServerAsync(ServerOptions(certificate), ct).ConfigureAwait(false);
        return ssl;
    }

    /// <summary>
    /// 生成（或读取）本机自签身份：P-256 ECDSA，Subject 为 CN=&lt;计算机名&gt;，有效期 10 年。
    /// KeyUsage 包含数字签名、密钥协商（TLS 认证），EKU 为客户/服务端认证。
    /// </summary>
    public static X509Certificate2 LoadOrCreateIdentity(string directory, string commonName)
    {
        Directory.CreateDirectory(directory);
        var certPath = Path.Combine(directory, "tls-cert.cer");
        var keyPath = Path.Combine(directory, "tls-key.pfx");
        if (File.Exists(certPath) && File.Exists(keyPath))
        {
            try
            {
                var loaded = X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(keyPath), null,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
                if (loaded.NotAfter > DateTime.UtcNow.AddDays(7))
                {
                    return loaded;
                }
            }
            catch (CryptographicException)
            {
                // 证书损坏：重建。
            }
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            $"CN={SanitizeCn(commonName)}",
            ecdsa,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement,
            critical: false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")],
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(ServerName);
        request.CertificateExtensions.Add(san.Build());

        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        var pfx = cert.Export(X509ContentType.Pkcs12);
        File.WriteAllBytes(keyPath, pfx);
        File.WriteAllBytes(certPath, cert.Export(X509ContentType.Cert));
        TryRestrictFile(keyPath);
        return X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
    }

    private static string SanitizeCn(string name) =>
        new(name.Where(c => c >= 0x20 && c != ',' && c != '=' && c != '+' && c != '<' && c != '>' && c != '#' && c != ';' && c != '"').Take(64).ToArray());

    private static void TryRestrictFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!System.OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                return;
            }

            var acl = info.GetAccessControl();
            acl.SetAccessRuleProtection(true, false);
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(me,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            info.SetAccessControl(acl);
        }
        catch (Exception)
        {
            // 权限收紧失败不影响功能。
        }
    }

    public static bool IsSelfSigned(X509Certificate2 cert)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        return chain.Build(cert) || cert.Subject == cert.Issuer;
    }
}
