#!/usr/bin/env bash
# iptun 服务端一键安装脚本（Ubuntu/Debian，root 运行）
# 用法：把 iptun-server 与本脚本放同一目录，执行  bash install.sh
set -e

INSTALL_DIR="/opt/iptun"
TUNNEL_PORT="${TUNNEL_PORT:-7000}"
WEB_PORT="${WEB_PORT:-8443}"
WEB_USER="${WEB_USER:-admin}"
WEB_PASS="${WEB_PASS:-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 12)}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YEL}[!]${NC} $*"; }

[ "$(id -u)" = "0" ] || { echo -e "${RED}请用 root 运行${NC}"; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)/iptun-server"
[ -f "$SRC" ] || { echo "找不到 iptun-server，请将它与 install.sh 放同一目录"; exit 1; }

command -v ip >/dev/null || { info "安装 iproute2/iptables"; apt-get update -qq && apt-get install -y -qq iproute2 iptables; }
[ -c /dev/net/tun ] || { warn "/dev/net/tun 不存在，部分 VPS 需在控制面板开启 TUN/TAP"; }

mkdir -p "$INSTALL_DIR"
install -m 755 "$SRC" "$INSTALL_DIR/iptun-server"

if [ ! -f "$INSTALL_DIR/clients.json" ]; then
  info "生成初始配置（示例两个客户端，请登录 Web 后修改）"
  cat > "$INSTALL_DIR/clients.json" <<EOF
{
  "tun_server_ip": "10.66.0.1",
  "tun_prefix": 24,
  "tunnel_port": $TUNNEL_PORT,
  "clients": [
    { "name": "A", "token": "change-me-A", "landing": "10.66.0.2", "enabled": false,
      "rules": [ { "proto": "all", "port_start": 1, "port_end": 10000 } ] },
    { "name": "B", "token": "change-me-B", "landing": "10.66.0.3", "enabled": false,
      "rules": [ { "proto": "all", "port_start": 10001, "port_end": 20000 } ] }
  ]
}
EOF
fi

cat > /etc/systemd/system/iptun.service <<EOF
[Unit]
Description=iptun public-IP landing tunnel server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/iptun-server -port $TUNNEL_PORT -config $INSTALL_DIR/clients.json -web :$WEB_PORT -webuser $WEB_USER -webpass $WEB_PASS
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iptun >/dev/null 2>&1
systemctl restart iptun
sleep 2
systemctl is-active iptun >/dev/null && info "服务已启动" || { echo "启动失败：journalctl -u iptun -e"; exit 1; }

PUBIP="$(curl -fsS --max-time 6 http://metadata.tencentyun.com/latest/meta-data/public-ipv4 2>/dev/null || hostname -I | awk '{print $1}')"
cat <<EOF

${GREEN}========== 安装完成 ==========${NC}
 Web 控制台 : https://$PUBIP:$WEB_PORT  （自签证书，浏览器提示不安全时点“高级→继续访问”）
 账号 / 密码: $WEB_USER / $WEB_PASS
 隧道端口   : UDP $TUNNEL_PORT（云安全组需放行）
 配置文件   : $INSTALL_DIR/clients.json
 TLS 证书   : $INSTALL_DIR/cert.pem（首次自动生成；删除后重启服务会重新生成）

 下一步：
  1. 云服务器安全组放行 TCP $WEB_PORT 与 UDP $TUNNEL_PORT，以及要转发的业务端口
  2. 浏览器打开 Web 控制台，新建客户端并分配端口段、获取 Token
  3. Windows 客户端（管理员）安装服务：
     iptun-client.exe -install -server $PUBIP:$TUNNEL_PORT -token <Token> -adapter IPTUNA
     sc start IPTunClient_IPTUNA

${YEL}注意：Token 在 Web 控制台创建客户端时生成，它同时是隧道加密根密钥，客户端 -token 必须与此一致。${NC}
EOF
