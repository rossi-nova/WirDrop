# WirDrop

Windows 上的 AirDrop 兼容客户端：与同一局域网内的 **iPhone、iPad、MacBook** 互传文件，不限制本机走有线还是无线。

参考实现：[seemoo-lab/opendrop](https://github.com/seemoo-lab/opendrop)、[t4t5/owly](https://github.com/t4t5/owly)。

## 功能

- **接收**：在 `_airdrop._tcp` 上公告自己，iPhone/Mac 的分享面板里会出现本机；
  `/Discover` → `/Ask`（弹窗确认）→ `/Upload` 三阶段，与 Apple 实现一致。
- **发送**：发现局域网内的 AirDrop 设备，`/Discover` 探测可见性后发 `/Ask`、流式 `/Upload`。
- **网卡**：自动优先选择物理网卡的局域网 IPv4 地址（Wi-Fi / 以太网 / USB 共享均可），
  可在界面顶部手动切换。
- **安全**：接收端只接受 `/Ask` 中列出的条目，拒绝 `..`、绝对路径、符号链接、
  Windows 保留名与双向控制符；解压在临时目录完成后才落地，重名自动加序号。

## 协议实现要点

| 层 | 实现 |
|---|---|
| 发现 | mDNS / DNS-SD，`_airdrop._tcp.local`，TXT `flags=0x089` |
| 传输 | TLS 1.2/1.3，接收端自签证书，双方不做对端认证 |
| HTTP | 严格 HTTP/1.1 分帧（拒绝歧义 `Content-Length`/`Transfer-Encoding`） |
| 报文 | 二进制 plist（`bplist00`），`/Discover`、`/Ask` 双向 |
| 归档 | CPIO `odc`（gzip）与 `newc` 读取；`/Upload` 支持 `application/x-cpio` 与 `application/x-dvzip` |

## 使用

1. 在本机 iPhone/Mac 的 AirDrop 设置里选择「所有人」。
2. 运行 `WirDrop.exe`，点击「启动」。
3. 在 iPhone/Mac 分享面板里选择本机名称即可发送；本机收到确认弹窗后点「接受」。
4. 从本机发送：把文件拖进窗口（发给选中设备），或双击设备列表中的设备选择文件。
5. 收到的文件保存在 `~/Downloads/WirDrop`。

## 构建

```powershell
dotnet build WirDrop.slnx -c Release
dotnet test src/WirDrop.Tests
dotnet run --project src/WirDrop.Windows
```

需要 .NET 10 SDK。发布单文件：

```powershell
dotnet publish src/WirDrop.Windows -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

## 验证现状

| 层面 | 结果 |
|---|---|
| 二进制 plist | 14 项单元测试 |
| CPIO odc/newc | OpenDrop/Owly 字节级向量逐字段比对 |
| DVZip | 5 条向量解压后 SHA-256 一致，自编码往返一致 |
| **Apple 线报文** | 10 项：Discover/Ask/Upload 的完整请求字节原样喂入，解析结果与 Apple 行为描述逐字段相符 |
| 线协议边界 | 8 项：单连接三阶段、Expect 100-continue、未列出条目、路径穿越、重名、legacy /Ask |
| 本机端到端 | 8 MB 真实 LAN 地址传输 41.4 MB/s，SHA-256 一致 |

共 38 项自动化测试。真机（iPhone/iPad/Mac）互操作需要实际设备参与，尚未在此环境实拍。

## 已知限制

- 「联系人」模式依赖 Apple 发放给 Apple ID 的身份记录，非 Apple 设备无法获得，因此
  对端必须设为「所有人」。
- iPhone 的「所有人」仅在 10 分钟内有效，之后自动回退到「联系人」。
- 防火墙未放行时会接收不到：需要在 Windows 防火墙中允许 `WirDrop.exe` 的入站 TCP。