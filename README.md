# iptun — 公网 IP 落地 / 多客户端端口分流隧道

把一台云服务器的公网 IP **按端口段**映射到你自己的机器（家里的电脑、客户现场的主机……），
本机任意 TCP/UDP 服务无需改造即可对公网提供访问，并且**服务看到的是访问者的真实公网 IP**，
不是 127.0.0.1，本机平时上网的出口 IP 也完全不变。

类似 frp / 自建内网穿透，但采用 **L3 三层 IP 透传 + 每客户端独立加密密钥**，并内置
Web 控制台、端口占用检测与 Windows 图形客户端。

---

## 特性

- **真实源 IP 透传**：在服务器上 DNAT 到隧道内网地址，由 conntrack 自动反向 NAT，
  SYN / HTTP / 游戏 / 任意协议的对端地址都是访客真实 IP。
- **一个公网 IP 多客户端分流**：按 `协议 + 端口段` 分配，例如
  `1–10000 → 客户端A`、`10001–20000 → 客户端B`，规则保存即热生效。
- **每客户端独立加密**：Token 既是身份凭证又是该客户端的 AES-256-GCM 根密钥，
  握手后经 HKDF 派生会话密钥；一个 Token 泄露不影响其他客户端。
- **内置 HTTPS Web 控制台**：Bootstrap 5 明亮主题（资源 go:embed 内嵌，无外部 CDN），
  客户端 / 端口段 / 隧道端口 / 在线状态 / 实时流量 / 系统负载管理，自签证书开箱即用。
- **智能端口例外**：除 SSH、面板、隧道三个端口强制保留外，通过内核 `-m socket`
  让 DNS / DHCP / chrony 等所有本机监听端口自动留在服务器，不会被误转发导致失联。
- **默认上网不变**：Windows 端用 wintun 三层网卡 + 高 metric 默认路由 + 主机路由防环回，
  只有访问落地 IP 的应答走隧道，日常浏览仍走本地网络。
- **成品化部署**：服务端一键 `install.sh` + systemd；Windows 端 GUI 一键装成系统服务
  （开机自启、崩溃重启），断线自动重连。

## 架构

```
访客 1.2.3.4 ──► 云服务器公网IP:8080
                     │ iptables DNAT（按端口段选落地地址）
                     ▼
                10.66.0.x（TUN iptun0）
                     │ AES-256-GCM over UDP（默认 7000）
                     ▼
              Windows 客户端 wintun 网卡
                     │ Windows 协议栈
                     ▼
              本机服务 0.0.0.0:8080   ← accept() 得到 1.2.3.4（真实源 IP）
```

- 服务端单 Go 二进制同时承担：TUN 数据面、加密 UDP、HTTPS 控制面。
- 云厂商 1:1 NAT（如腾讯云 EIP，网卡上是内网 IP）已适配。

## 目录结构

```
common/                 帧封装 / AES-GCM / HKDF
cmd/server/             Linux 服务端（数据面 + Web 控制台 + 端口检测）
  assets/               内嵌前端（index.html + 本地 Bootstrap）
  netconfig_linux.go    TUN 地址、iptables DNAT/socket 例外
  cert.go               自签 TLS 证书自动生成
cmd/client/             Windows 客户端（wintun、路由、Windows 服务、状态文件）
gui/IptunGui.cs         Windows 图形设置程序（WinForms，系统自带 csc 编译）
deploy/install.sh       服务端一键安装
```

## 服务端部署（Ubuntu / Debian，root）

```bash
# 交叉编译（或在服务器上 go build）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o iptun-server ./cmd/server

# 上传 iptun-server 与 deploy/install.sh 到同一目录后：
bash install.sh
```

脚本会安装 systemd 服务、生成自签证书与**随机 Web 密码**、放行所需端口并打印
控制台地址与密码。也可用环境变量覆盖：`TUNNEL_PORT`、`WEB_PORT`、`WEB_USER`、`WEB_PASS`。

云安全组记得放行：TCP 面板端口、UDP 隧道端口、以及要转发的业务端口。

启动参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-port` | 7000 | 隧道 UDP 端口（也可在 Web 后台热改） |
| `-web` | `:8443` | Web 控制台监听（HTTPS） |
| `-webuser` / `-webpass` | admin / 留空随机 | 管理员账号密码，密码也可在后台修改持久化 |
| `-config` | /root/iptun/clients.json | 客户端配置（Web 保存自动写回） |
| `-cert` / `-certkey` | 自动生成 | 自签证书路径 |

## 客户端使用（Windows 10/11 x64）

需要管理员权限与同目录的官方 `wintun.dll`。

**图形界面（推荐）**：运行 `iptun-gui.exe`（源码在 `gui/`，用
`gui/build-gui.ps1` 编译），填写「服务器地址 / Token / 实例名称」→ 保存并启动。

**命令行**：

```bat
:: 安装为开机自启服务
iptun-client.exe -install -server 1.2.3.4:7000 -token <Web后台发放的Token> -adapter IPTun
sc start IPTunClient_IPTun

:: 或前台调试
iptun-client.exe -server 1.2.3.4:7000 -token <Token>

:: 卸载
iptun-client.exe -uninstall -adapter IPTun
```

在 Web 控制台「客户端」页新建客户端、分配协议与端口段并获取 Token；编辑端口段时
会实时检测保留端口、本机占用与客户端间重叠（本机占用端口自动作为例外提示）。

## 安全模型

- 数据面：每帧 `类型 + 12字节 nonce + AES-256-GCM(密文+16字节认证标签)`，
  防窃听、防篡改；会话密钥每次连接随机协商。
- 身份：只有持有正确 Token 才能完成 GCM 握手；Token 在 Web 后台吊销即时生效。
- 控制面：自签 TLS（可替换为正式证书），会话 Cookie 带 HttpOnly/Secure，
  默认密码首启随机生成。
- 端口：SSH / 面板 / 隧道三端口动态保留，其余本机监听端口经 `-m socket` 自动留本地。

> 自签证书浏览器首次访问会有安全提示，选择继续即可；也可把 `cert.pem` 导入本机
> 受信任根证书颁发机构，或自行替换为域名正式证书。

## 构建

```bash
# 服务端（Linux）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o iptun-server ./cmd/server
# 客户端（Windows，需在能取到 golang.zx2c4.com/wintun 的环境）
GOOS=windows GOARCH=amd64 go build -o iptun-client.exe ./cmd/client
# GUI：在 Windows 上运行 gui/build-gui.ps1（调用系统自带 .NET Framework csc）
```

## 免责声明

仅供对自有设备与自有云服务器进行合法远程管理、学习网络与虚拟化技术使用。
请遵守所在地法律法规与云服务商条款，不得用于绕过未授权网络访问或隐藏身份。

## License

[MIT](LICENSE)
