#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V2.8.0 (Axiom - BadVPN Restore)
#
# [CHANGELOG]
# - [RESTORE] 恢复 BadVPN-UDPGW 的编译和部署流程。
# - [CONFIG] 重新启用 7300 端口配置。
# ==========================================================

# =============================
# 1. 文件路径定义 (全局变量)
# =============================
REPO_ROOT=$(dirname "$0")

# 核心目录
PANEL_DIR="/etc/wss-panel"
UDP_CUSTOM_DIR="$PANEL_DIR/udp-custom"
mkdir -p "$PANEL_DIR" 
mkdir -p "$UDP_CUSTOM_DIR"

# 日志与配置
WSS_LOG_FILE="/var/log/wss.log" 
CONFIG_PATH="$PANEL_DIR/config.json"
UDP_CUSTOM_CONFIG_PATH="$UDP_CUSTOM_DIR/config.json"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
INTERNAL_SECRET_PATH="$PANEL_DIR/internal_secret.txt" 
IPTABLES_RULES="/etc/iptables/rules.v4"
DB_PATH="$PANEL_DIR/wss_panel.db"

# 二进制文件路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
UDP_CUSTOM_BIN_PATH="/usr/local/bin/udp-custom" 
UDPGW_BIN_PATH="/usr/local/bin/badvpn-udpgw" # [RESTORED]

# 面板文件路径
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"
TG_BOT_LOGIC_DEST="$PANEL_DIR/tg_bot_logic.js"

# SSHD Stunnel 路径
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"

# BadVPN 源码路径
BADVPN_SRC_DIR="/root/badvpn" 

# Systemd 服务路径 (Target)
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service" # [RESTORED]
UDP_CUSTOM_SERVICE_PATH="/etc/systemd/system/wss-udp-custom.service"

# Systemd 模板路径 (Source)
WSS_TEMPLATE="$REPO_ROOT/wss.service.template"
PANEL_TEMPLATE="$REPO_ROOT/wss_panel.service.template"
UDPGW_TEMPLATE="$REPO_ROOT/udpgw.service.template" # [RESTORED]
UDP_CUSTOM_TEMPLATE="$REPO_ROOT/wss-udp-custom.service.template"

# 创建日志目录
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
touch "$WSS_LOG_FILE"

# =============================
# 2. 交互式端口和用户配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (V2.8.0) ===="
echo "请确认或修改以下端口和服务用户设置 (回车以使用默认值)。"

# 1. 端口
read -p "  1. WSS HTTP 端口 [80]: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "  2. WSS TLS 端口 [443]: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "  3. Stunnel (SSH/TLS) 端口 [444]: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

# [RESTORED]
read -p "  4. BadVPN UDPGW 端口 (本地回环) [7300]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "  5. UDP Custom (HTTP Custom) 端口 [7400]: " UDP_CUSTOM_PORT
UDP_CUSTOM_PORT=${UDP_CUSTOM_PORT:-7400}

read -p "  6. Web 面板端口 [54321]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

read -p "  7. 内部 SSH (WSS) 转发端口 [22]: " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}

read -p "  8. 内部 SSH (Stunnel) 转发端口 [2222]: " SSHD_STUNNEL_PORT
SSHD_STUNNEL_PORT=${SSHD_STUNNEL_PORT:-2222}

# 2. 服务用户 (最小权限)
read -p "  9. Panel 服务用户名 [admin]: " panel_user
panel_user=${panel_user:-admin}
panel_user=$(echo "$panel_user" | tr -d '\n' | tr -d '\r' | xargs)

# [TG_BOT] 3. Telegram 机器人配置
echo "----------------------------------"
echo "==== Telegram 机器人配置 (可选) ===="
read -p "  10. 机器人 Token (留空跳过): " TG_BOT_TOKEN
TG_BOT_TOKEN=${TG_BOT_TOKEN:-""}
TG_BOT_TOKEN=$(echo "$TG_BOT_TOKEN" | tr -d '\n' | tr -d '\r' | xargs)

TG_ADMIN_ID=""
if [ -n "$TG_BOT_TOKEN" ]; then
    read -p "  11. 管理员 Telegram ID (数字 ID): " TG_ADMIN_ID
    if [ -z "$TG_ADMIN_ID" ]; then
        echo "警告: 未提供管理员 ID，机器人将被禁用以策安全。"
        TG_BOT_TOKEN=""
    fi
fi
TG_ADMIN_ID=$(echo "$TG_ADMIN_ID" | tr -d '\n' | tr -d '\r' | xargs)

# --- IPC 端口配置 ---
INTERNAL_API_PORT=54322 
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"

echo "---------------------------------"
echo "配置确认："
echo "Panel 用户: '$panel_user'"
echo "WSS (80/443) -> $WSS_HTTP_PORT/$WSS_TLS_PORT"
echo "Stunnel (444) -> $STUNNEL_PORT"
echo "BadVPN UDPGW -> 127.0.0.1:$UDPGW_PORT (Local TCP)"
echo "UDP Custom -> $UDP_CUSTOM_PORT"
echo "Web Panel -> $PANEL_PORT"
if [ -n "$TG_BOT_TOKEN" ]; then
    echo "Telegram Bot: 已启用 (Admin: $TG_ADMIN_ID)"
else
    echo "Telegram Bot: 未启用"
fi
echo "---------------------------------"

# 交互式设置 ROOT 密码
if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。"
else
    echo "==== 管理面板配置 (首次或重置) ===="
    echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
    while true; do
      read -s -p "面板密码: " pw1 && echo
      read -s -p "请再次确认密码: " pw2 && echo
      if [ -z "$pw1" ]; then
        echo "密码不能为空，请重新输入。"
        continue
      fi
      if [ "$pw1" != "$pw2" ]; then
        echo "两次输入不一致，请重试。"
        continue
      fi
      PANEL_ROOT_PASS_RAW="$pw1"
      break
    done
fi

echo "----------------------------------"
echo "==== 3. 系统清理与服务停止 ===="
systemctl stop wss stunnel4 udpgw wss-udp-custom wss_panel sshd_stunnel || true
# 注意：我们不再删除 udpgw 服务，因为我们要重装它

apt update -y
if ! command -v node >/dev/null; then
    echo "正在安装 Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# [RESTORE] 添加 cmake 和编译工具
echo "正在安装基础依赖 (包含 cmake)..."
apt install -y wget curl git net-tools openssl stunnel4 iproute2 iptables procps libsqlite3-dev passwd sudo cmake build-essential || echo "警告: 依赖安装失败。"

# 创建用户
if ! id -u "$panel_user" >/dev/null 2>&1; then
    echo "创建系统用户: $panel_user"
    adduser --system --no-create-home --group "$panel_user" || adduser --system --no-create-home "$panel_user"
fi
if ! getent group "$panel_user" >/dev/null; then
    groupadd "$panel_user"
    usermod -a -G "$panel_user" "$panel_user"
fi

echo "安装 Node.js 依赖..."
cp "$REPO_ROOT/package.json" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
if ! npm install --production; then
    echo "警告: Node.js 依赖安装失败，但这可能是网络问题。"
fi
echo "正在安装 Telegram Bot 依赖..."
npm install node-telegram-bot-api || echo "Telegram Bot 依赖安装失败，Bot 功能可能不可用。"

# 处理密钥
if [ ! -f "$ROOT_HASH_FILE" ] && [ -n "${PANEL_ROOT_PASS_RAW:-}" ]; then
    PANEL_ROOT_PASS_HASH=$(node -e "const bcrypt = require('bcrypt'); const hash = bcrypt.hashSync('$PANEL_ROOT_PASS_RAW', 12); console.log(hash);")
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
fi

if [ ! -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

if [ ! -f "$INTERNAL_SECRET_PATH" ]; then
    INTERNAL_SECRET=$(openssl rand -hex 32)
    echo "$INTERNAL_SECRET" > "$INTERNAL_SECRET_PATH"
fi
INTERNAL_SECRET=$(cat "$INTERNAL_SECRET_PATH")

chmod 600 "$ROOT_HASH_FILE" "$SECRET_KEY_FILE" "$INTERNAL_SECRET_PATH"

# 生成主配置文件
echo "正在创建 config.json..."
tee "$CONFIG_PATH" > /dev/null <<EOF
{
  "panel_user": "$panel_user",
  "panel_port": $PANEL_PORT,
  "wss_http_port": $WSS_HTTP_PORT,
  "wss_tls_port": $WSS_TLS_PORT,
  "stunnel_port": $STUNNEL_PORT,
  "udpgw_port": $UDPGW_PORT,
  "udp_custom_port": $UDP_CUSTOM_PORT,
  "internal_forward_port": $INTERNAL_FORWARD_PORT,
  "internal_api_port": $INTERNAL_API_PORT,
  "internal_api_secret": "$INTERNAL_SECRET",
  "panel_api_url": "$PANEL_API_URL",
  "proxy_api_url": "$PROXY_API_URL",
  "tg_bot_token": "$TG_BOT_TOKEN",
  "tg_admin_id": "$TG_ADMIN_ID"
}
EOF
chmod 600 "$CONFIG_PATH"
clean_user=$(echo "$panel_user" | xargs)
chown "$clean_user:$clean_user" "$CONFIG_PATH"

echo "正在创建 UDP Custom 配置文件..."
tee "$UDP_CUSTOM_CONFIG_PATH" > /dev/null <<EOF
{
  "listen": ":$UDP_CUSTOM_PORT",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF
chmod 600 "$UDP_CUSTOM_CONFIG_PATH"
echo "----------------------------------"

# =============================
# [NEW] 编译 BadVPN UDPGW
# =============================
compile_badvpn() {
    echo "==== 编译 BadVPN UDPGW ===="
    if command -v badvpn-udpgw >/dev/null 2>&1; then
        echo "检测到 badvpn-udpgw 已安装，跳过编译。"
        # 复制到标准路径以防万一
        cp $(which badvpn-udpgw) "$UDPGW_BIN_PATH" || true
        return
    fi

    echo "正在从 GitHub 克隆 BadVPN 源码..."
    rm -rf "$BADVPN_SRC_DIR"
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_SRC_DIR" || {
        echo "错误: 无法克隆 BadVPN 仓库。"
        return 1
    }

    echo "开始编译..."
    mkdir -p "$BADVPN_SRC_DIR/badvpn-build"
    cd "$BADVPN_SRC_DIR/badvpn-build"
    
    # 只编译 UDPGW
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make

    echo "安装二进制文件..."
    cp udpgw/badvpn-udpgw "$UDPGW_BIN_PATH"
    chmod +x "$UDPGW_BIN_PATH"
    echo "BadVPN 编译安装完成。"
}

# 执行编译
compile_badvpn

echo "----------------------------------"


# =============================
# 4. 配置 Sudoers
# =============================
echo "==== 配置 Sudoers ===="
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
CMD_USERADD=$(command -v useradd)
CMD_USERMOD=$(command -v usermod)
CMD_USERDEL=$(command -v userdel)
CMD_GPGPASSWD=$(command -v gpasswd)
CMD_CHPASSWD=$(command -v chpasswd)
CMD_PKILL=$(command -v pkill)
CMD_IPTABLES=$(command -v iptables)
CMD_IPTABLES_SAVE=$(command -v iptables-save)
CMD_JOURNALCTL=$(command -v journalctl)
CMD_SYSTEMCTL=$(command -v systemctl)
CMD_GETENT=$(command -v getent)
CMD_SED=$(command -v sed)

# [RESTORE] 恢复 udpgw 的 restart 权限 (如果需要面板控制它的话，虽然通常不需要)
tee "$SUDOERS_FILE" > /dev/null <<EOF
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERADD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERMOD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERDEL
$panel_user ALL=(ALL) NOPASSWD: $CMD_GPGPASSWD
$panel_user ALL=(ALL) NOPASSWD: $CMD_CHPASSWD
$panel_user ALL=(ALL) NOPASSWD: $CMD_PKILL
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES_SAVE
$panel_user ALL=(ALL) NOPASSWD: $CMD_JOURNALCTL
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: $CMD_GETENT
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: $CMD_SED
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL daemon-reload
EOF

chmod 440 "$SUDOERS_FILE"
echo "Sudoers 配置完成。"
echo "----------------------------------"


# =============================
# 5. 内核调优
# =============================
echo "==== 配置内核参数 ===="
sed -i '/# WSS_NET_START/,/# WSS_NET_END/d' /etc/sysctl.conf
# [RESTORE] 增加 socket buffer，这对 BadVPN 很重要
cat >> /etc/sysctl.conf <<EOF
# WSS_NET_START
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65536
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 5
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
# WSS_NET_END
EOF
sysctl -p > /dev/null
echo "----------------------------------"

# =============================
# 6. 部署代码文件
# =============================
echo "==== 部署代码文件 ===="
cp "$REPO_ROOT/wss_proxy.js" "$WSS_PROXY_PATH"
chmod +x "$WSS_PROXY_PATH"
cp "$REPO_ROOT/wss_panel.js" "$PANEL_BACKEND_DEST"
chmod +x "$PANEL_BACKEND_DEST"
cp "$REPO_ROOT/index.html" "$PANEL_HTML_DEST"
cp "$REPO_ROOT/app.js" "$PANEL_JS_DEST"
cp "$REPO_ROOT/login.html" "$LOGIN_HTML_DEST"
if [ -f "$REPO_ROOT/tg_bot_logic.js" ]; then
    cp "$REPO_ROOT/tg_bot_logic.js" "$TG_BOT_LOGIC_DEST"
fi

if [ ! -f "$DB_PATH" ]; then echo "Database will be initialized on start."; fi
[ ! -f "$WSS_LOG_FILE" ] && touch "$WSS_LOG_FILE"
[ ! -f "$PANEL_DIR/audit.log" ] && touch "$PANEL_DIR/audit.log"
[ ! -f "$PANEL_DIR/hosts.json" ] && echo '[]' > "$PANEL_DIR/hosts.json"

# 部署 UDP Custom
echo "正在下载 UDP Custom 二进制文件..."
if wget "https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64" -O "$UDP_CUSTOM_BIN_PATH"; then
    chmod +x "$UDP_CUSTOM_BIN_PATH"
    echo "UDP Custom 下载成功。"
else
    echo "严重错误：无法下载 UDP Custom。请检查网络。"
    touch "$UDP_CUSTOM_BIN_PATH"
    chmod +x "$UDP_CUSTOM_BIN_PATH"
fi
echo "----------------------------------"


# =============================
# 7. 安装 Stunnel4
# =============================
echo "==== 重新安装 Stunnel4 ===="
if ! getent group shell_users >/dev/null; then groupadd shell_users; fi

openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem
chmod 600 /etc/stunnel/certs/*.key
chmod 600 /etc/stunnel/certs/*.pem

tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$SSHD_STUNNEL_PORT
EOF

systemctl enable stunnel4
systemctl restart stunnel4
echo "----------------------------------"


# =============================
# 9. 部署 Systemd 服务
# =============================
echo "==== 部署 Systemd 服务 ===="

# wss service
if [ ! -f "$WSS_TEMPLATE" ]; then echo "错误: 找不到 wss template"; exit 1; fi
cp "$WSS_TEMPLATE" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_PROXY_SCRIPT_PATH@|$WSS_PROXY_PATH|g" "$WSS_SERVICE_PATH"

# wss_panel service
if [ ! -f "$PANEL_TEMPLATE" ]; then echo "错误: 找不到 panel template"; exit 1; fi
cp "$PANEL_TEMPLATE" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_USER@|$panel_user|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_BACKEND_SCRIPT_PATH@|$PANEL_BACKEND_FILE|g" "$PANEL_SERVICE_PATH"

# udpgw service (RESTORED)
if [ ! -f "$UDPGW_TEMPLATE" ]; then echo "错误: 找不到 udpgw template"; exit 1; fi
cp "$UDPGW_TEMPLATE" "$UDPGW_SERVICE_PATH"
# 注意：udpgw.service.template 中需要占位符 @UDPGW_PORT@，我们来检查一下内容
sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$UDPGW_SERVICE_PATH"
# 修复二进制路径（模板可能是 /root/... 我们要改为 /usr/local/bin/）
sed -i "s|ExecStart=.*|ExecStart=$UDPGW_BIN_PATH --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 9999 --max-connections-for-client 9999 --client-socket-sndbuf 8388608|g" "$UDPGW_SERVICE_PATH"


# udp custom service
if [ ! -f "$UDP_CUSTOM_TEMPLATE" ]; then echo "错误: 找不到 udp custom template"; exit 1; fi
cp "$UDP_CUSTOM_TEMPLATE" "$UDP_CUSTOM_SERVICE_PATH"
sed -i "s|@UDP_CUSTOM_DIR@|$UDP_CUSTOM_DIR|g" "$UDP_CUSTOM_SERVICE_PATH"
sed -i "s|@UDP_CUSTOM_BIN_PATH@|$UDP_CUSTOM_BIN_PATH|g" "$UDP_CUSTOM_SERVICE_PATH"

chown -R "$clean_user:$clean_user" "$PANEL_DIR"
chown "$clean_user:$clean_user" "$WSS_LOG_FILE"
chown "$clean_user:$clean_user" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"
chmod 600 "$UDP_CUSTOM_CONFIG_PATH"

systemctl daemon-reload
systemctl enable wss_panel
systemctl enable wss
systemctl enable udpgw
systemctl enable wss-udp-custom

# 重启服务
systemctl restart udpgw # 先启动 udpgw
systemctl restart wss_panel
systemctl restart wss
systemctl restart wss-udp-custom
echo "----------------------------------"

# =============================
# 10. IPTABLES & 全端口转发
# =============================
echo "==== 配置 IPTABLES (全端口 UDP 劫持 -> $UDP_CUSTOM_PORT) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
UDP_REDIR_CHAIN="WSS_UDP_REDIR" 

iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

iptables -t nat -F $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -X $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -N $UDP_REDIR_CHAIN 2>/dev/null || true

iptables -t nat -D PREROUTING -p udp -j $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -I PREROUTING -p udp -j $UDP_REDIR_CHAIN

# 排除规则
echo "  - 排除 UDP Custom ($UDP_CUSTOM_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDP_CUSTOM_PORT -j RETURN
echo "  - 排除 BadVPN UDPGW (Native Loopback)" 
# BadVPN 监听在 127.0.0.1，不需要 NAT 排除，因为它不接收外部流量。

iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 53 -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $WSS_HTTP_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $WSS_TLS_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $PANEL_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 22 -j RETURN

# 重定向
echo "  - 启用全端口劫持 (REDIRECT -> $UDP_CUSTOM_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp -j REDIRECT --to-ports $UDP_CUSTOM_PORT

# 放行规则
iptables -I INPUT -p tcp --dport $WSS_HTTP_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $WSS_TLS_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $STUNNEL_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $PANEL_PORT -j ACCEPT
iptables -I INPUT -p udp --dport $UDP_CUSTOM_PORT -j ACCEPT

if ! command -v netfilter-persistent >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent || true
fi
if command -v netfilter-persistent >/dev/null; then
    /sbin/iptables-save > "$IPTABLES_RULES"
    systemctl enable netfilter-persistent || true
    systemctl start netfilter-persistent || true
fi
echo "----------------------------------"

# =============================
# 11. SSHD 配置
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
if ! grep -q "^Port $INTERNAL_FORWARD_PORT" "$SSHD_CONFIG" && [ "$INTERNAL_FORWARD_PORT" != "22" ]; then
    sed -i -E "/^[#\s]*Port /d" "$SSHD_CONFIG"
    echo "Port $INTERNAL_FORWARD_PORT" >> "$SSHD_CONFIG"
fi
cat >> "$SSHD_CONFIG" <<EOF
# WSS_TUNNEL_BLOCK_START
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    AllowTcpForwarding yes
# WSS_TUNNEL_BLOCK_END
EOF

cp "$SSHD_CONFIG" "$SSHD_STUNNEL_CONFIG"
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_STUNNEL_CONFIG"
sed -i -E "/^[#\s]*Port /d" "$SSHD_STUNNEL_CONFIG"
sed -i -E "/^[#\s]*ListenAddress /d" "$SSHD_STUNNEL_CONFIG"
cat >> "$SSHD_STUNNEL_CONFIG" <<EOF
# WSS_STUNNEL_BLOCK_START
Port $SSHD_STUNNEL_PORT
ListenAddress 127.0.0.1
ListenAddress ::1
PasswordAuthentication yes
KbdInteractiveAuthentication yes
AllowTcpForwarding yes
AllowGroups shell_users
# WSS_STUNNEL_BLOCK_END
EOF

tee "$SSHD_STUNNEL_SERVICE" > /dev/null <<EOF
[Unit]
Description=OpenSSH Stunnel Service
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run
[Service]
ExecStart=/usr/sbin/sshd -D -f $SSHD_STUNNEL_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s
[Install]
WantedBy=multi-user.target
EOF

chmod 600 "$SSHD_CONFIG"
chmod 600 "$SSHD_STUNNEL_CONFIG"
systemctl daemon-reload
systemctl restart sshd
systemctl enable sshd_stunnel
systemctl restart sshd_stunnel

# Final Restart
systemctl restart stunnel4 wss_panel wss udpgw wss-udp-custom

echo "=================================================="
echo "✅ 部署完成！(Axiom V2.8.0 - BadVPN Restored)"
echo "   - UDPGW: 127.0.0.1:$UDPGW_PORT (Binary Mode)"
echo "   - UDP Custom: 0.0.0.0:$UDP_CUSTOM_PORT"
echo "   - TG Bot: ${TG_BOT_TOKEN:+ENABLED}"
echo "=================================================="
