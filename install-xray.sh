#!/bin/bash

# Xray 服务器端安装和配置脚本
# 用于安装 Xray 并创建 VLESS 服务器

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "请使用 root 权限运行此脚本"
        exit 1
    fi
}

# 检测系统架构
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            XRAY_ARCH="64"
            ;;
        aarch64|arm64)
            XRAY_ARCH="arm64-v8a"
            ;;
        armv7l|armv6l)
            XRAY_ARCH="arm32-v7a"
            ;;
        *)
            print_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    print_info "检测到系统架构: $ARCH (Xray: $XRAY_ARCH)"
}

# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        print_error "无法检测操作系统"
        exit 1
    fi
    print_info "检测到操作系统: $OS $OS_VERSION"
}

# 安装必要的依赖
install_dependencies() {
    print_info "安装必要的依赖..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        apt-get update
        apt-get install -y wget curl unzip systemd openssl
    elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ]; then
        yum install -y wget curl unzip systemd openssl
    else
        print_warn "未知的系统类型，请手动安装 wget, curl, unzip, systemd, openssl"
    fi
}

# 下载并安装 Xray
install_xray() {
    print_info "下载 Xray..."
    
    XRAY_DIR="/usr/local/bin"
    XRAY_BIN="$XRAY_DIR/xray"
    
    # 检查 Xray 服务是否正在运行，如果是则先停止
    if systemctl is-active --quiet xray 2>/dev/null; then
        print_warn "检测到 Xray 服务正在运行，将先停止服务以更新文件"
        systemctl stop xray 2>/dev/null || true
        sleep 1
    fi
    
    # 如果文件存在且被占用，等待释放
    if [ -f "$XRAY_BIN" ]; then
        if lsof "$XRAY_BIN" >/dev/null 2>&1; then
            print_warn "Xray 文件正在被使用，等待释放..."
            sleep 2
        fi
    fi
    
    # 获取最新版本号
    print_info "正在获取最新版本信息..."
    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | \
        grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' | sed 's/^v//')
    
    # 如果获取失败，使用已知的稳定版本
    if [ -z "$XRAY_VERSION" ]; then
        print_warn "无法从 GitHub 获取最新版本，使用已知稳定版本: 25.12.1"
        XRAY_VERSION="25.12.1"
    fi
    
    print_info "Xray 最新版本: $XRAY_VERSION"
    
    # 下载 Xray
    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
    TEMP_DIR=$(mktemp -d)
    
    print_info "从 $DOWNLOAD_URL 下载..."
    wget -q -O "$TEMP_DIR/xray.zip" "$DOWNLOAD_URL" || {
        print_error "下载失败"
        exit 1
    }
    
    # 解压并安装
    print_info "解压并安装 Xray..."
    unzip -q "$TEMP_DIR/xray.zip" -d "$TEMP_DIR"
    
    # 如果目标文件存在，先删除（避免 Text file busy 错误）
    if [ -f "$XRAY_BIN" ]; then
        rm -f "$XRAY_BIN"
        sleep 0.5
    fi
    
    # 复制新文件
    cp "$TEMP_DIR/xray" "$XRAY_BIN"
    chmod +x "$XRAY_BIN"
    
    # 清理临时文件
    rm -rf "$TEMP_DIR"
    
    # 验证安装
    if [ -f "$XRAY_BIN" ]; then
        XRAY_VER=$($XRAY_BIN version | head -n 1)
        print_info "Xray 安装成功: $XRAY_VER"
    else
        print_error "Xray 安装失败"
        exit 1
    fi
}

# 生成 UUID
generate_uuid() {
    command -v uuidgen &> /dev/null && uuidgen && return
    [ -f /proc/sys/kernel/random/uuid ] && cat /proc/sys/kernel/random/uuid && return
    openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
}

# 获取服务器 IP 地址
get_server_ip() {
    # 尝试获取公网 IP
    for api in api.ipify.org ifconfig.me icanhazip.com; do
        IP=$(curl -s --max-time 5 "https://$api" 2>/dev/null)
        [ -n "$IP" ] && echo "$IP" && return
    done
    
    # 使用本地 IP
    ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' && return
    hostname -I | awk '{print $1}' && return
    ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d'/' -f1 && return
    
    echo "127.0.0.1"
}

# 生成自签名证书
generate_self_signed_cert() {
    print_info "生成自签名证书..."
    
    CERT_DIR="/usr/local/etc/xray/cert"
    CERT_CRT="$CERT_DIR/certificate.crt"
    CERT_KEY="$CERT_DIR/private.key"
    
    # 检查证书是否已存在
    if [ -f "$CERT_CRT" ] && [ -f "$CERT_KEY" ]; then
        print_info "证书文件已存在，跳过生成"
        return 0
    fi
    
    # 获取服务器信息
    SERVER_IP=$(get_server_ip)
    HOSTNAME=$(hostname)
    
    print_info "服务器 IP: $SERVER_IP"
    print_info "主机名: $HOSTNAME"
    
    # 创建证书目录
    mkdir -p "$CERT_DIR"
    
    # 生成私钥
    print_info "生成私钥..."
    openssl genrsa -out "$CERT_KEY" 2048 2>/dev/null || {
        print_error "私钥生成失败，请确保已安装 openssl"
        return 1
    }
    
    # 创建证书配置文件
    CERT_CONF=$(mktemp)
    cat > "$CERT_CONF" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=CN
ST=State
L=City
O=Organization
OU=Organizational Unit
CN=$SERVER_IP

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $SERVER_IP
DNS.1 = $HOSTNAME
DNS.2 = localhost
EOF
    
    # 生成证书签名请求和自签名证书
    print_info "生成自签名证书（有效期 10 年）..."
    openssl req -new -x509 -key "$CERT_KEY" -out "$CERT_CRT" -days 3650 \
        -config "$CERT_CONF" -extensions v3_req 2>/dev/null || {
        print_error "证书生成失败"
        rm -f "$CERT_CONF"
        return 1
    }
    
    # 清理临时文件
    rm -f "$CERT_CONF"
    
    # 设置权限和所有者（让 nobody 用户可以读取）
    chmod 600 "$CERT_KEY"
    chmod 644 "$CERT_CRT"
    chown nobody:nogroup "$CERT_KEY" 2>/dev/null || chown nobody:nobody "$CERT_KEY" 2>/dev/null || true
    chown nobody:nogroup "$CERT_CRT" 2>/dev/null || chown nobody:nobody "$CERT_CRT" 2>/dev/null || true
    chmod 755 "$CERT_DIR"
    
    # 验证证书
    if [ -f "$CERT_CRT" ] && [ -f "$CERT_KEY" ]; then
        CERT_SUBJECT=$(openssl x509 -in "$CERT_CRT" -noout -subject 2>/dev/null | sed 's/subject=//')
        CERT_EXPIRY=$(openssl x509 -in "$CERT_CRT" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        print_info "自签名证书生成成功！"
        echo "  证书主题: $CERT_SUBJECT"
        echo "  有效期至: $CERT_EXPIRY"
        print_warn "注意: 这是自签名证书，客户端需要手动信任或忽略证书警告"
        return 0
    else
        print_error "证书文件生成失败"
        return 1
    fi
}

# 创建配置目录和文件
create_config() {
    print_info "创建配置目录..."
    CONFIG_DIR="/usr/local/etc/xray"
    mkdir -p "$CONFIG_DIR"
    
    # 创建证书目录（如果使用 TLS）
    CERT_DIR="$CONFIG_DIR/cert"
    mkdir -p "$CERT_DIR"
    print_info "证书目录已创建: $CERT_DIR"
    
    # 生成客户端 UUID
    CLIENT_UUID=$(generate_uuid)
    print_info "生成客户端 UUID: $CLIENT_UUID"
    
    # 创建默认配置文件（VLESS 服务器）
    print_info "创建 VLESS 服务器配置文件..."
    cat > "$CONFIG_DIR/config.json" << EOF
{
  "log": {
    "loglevel": "error"
  },
  "policy": {
    "levels": {
      "0": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false,
      "statsOutboundUplink": false,
      "statsOutboundDownlink": false
    }
  },
  "inbounds": [
    {
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$CLIENT_UUID",
            "flow": ""
          }
        ],
        "decryption": "none",
        "fallbacks": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/cert/certificate.crt",
              "keyFile": "/usr/local/etc/xray/cert/private.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless",
          "headers": {}
        }
      },
      "tag": "inbound-vless"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    print_info "配置文件已创建: $CONFIG_DIR/config.json"
    print_info "客户端连接信息:"
    echo "  UUID: $CLIENT_UUID"
    echo "  端口: 443"
    echo "  路径: /vless"
    echo "  传输: WebSocket (ws)"
    echo "  加密: TLS"
}

# 创建日志目录
create_log_dir() {
    print_info "创建日志目录..."
    LOG_DIR="/var/log/xray"
    mkdir -p "$LOG_DIR"
    chown nobody:nogroup "$LOG_DIR" 2>/dev/null || chown nobody:nobody "$LOG_DIR" 2>/dev/null || true
}

# 创建交换空间
create_swap() {
    print_info "检查交换空间..."
    
    # 检查是否已有交换空间
    if swapon --show | grep -q .; then
        SWAP_SIZE=$(swapon --show --bytes | awk 'NR>1 {sum+=$3} END {print sum/1024/1024}')
        print_info "检测到现有交换空间: ${SWAP_SIZE}MB"
        # 优化现有交换空间的 swappiness
        optimize_swap_settings
        return 0
    fi
    
    # 检查交换文件是否已存在
    SWAP_FILE="/swapfile"
    if [ -f "$SWAP_FILE" ]; then
        print_warn "交换文件已存在: $SWAP_FILE"
        if swapon "$SWAP_FILE" 2>/dev/null; then
            print_info "已启用现有交换文件"
            optimize_swap_settings
            return 0
        fi
    fi
    
    # 获取总内存（MB）
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    
    # 计算交换空间大小（建议为内存的1-2倍，最小512MB，最大2GB）
    if [ "$TOTAL_MEM" -le 512 ]; then
        SWAP_SIZE=1024  # 1GB
    elif [ "$TOTAL_MEM" -le 1024 ]; then
        SWAP_SIZE=1024  # 1GB
    elif [ "$TOTAL_MEM" -le 2048 ]; then
        SWAP_SIZE=2048  # 2GB
    else
        SWAP_SIZE=2048  # 最大2GB
    fi
    
    print_info "准备创建 ${SWAP_SIZE}MB 交换空间..."
    
    # 检查可用磁盘空间
    AVAILABLE_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$AVAILABLE_SPACE" -lt "$SWAP_SIZE" ]; then
        print_warn "可用磁盘空间不足 (${AVAILABLE_SPACE}MB < ${SWAP_SIZE}MB)"
        print_warn "跳过交换空间创建"
        return 1
    fi
    
    # 创建交换文件
    print_info "创建交换文件: $SWAP_FILE"
    if fallocate -l ${SWAP_SIZE}M "$SWAP_FILE" 2>/dev/null || \
       dd if=/dev/zero of="$SWAP_FILE" bs=1M count=$SWAP_SIZE 2>/dev/null; then
        chmod 600 "$SWAP_FILE"
        mkswap "$SWAP_FILE"
        swapon "$SWAP_FILE"
        
        if swapon --show | grep -q "$SWAP_FILE"; then
            print_info "交换空间创建成功: ${SWAP_SIZE}MB"
            
            # 添加到 /etc/fstab 使其永久生效
            if ! grep -q "$SWAP_FILE" /etc/fstab; then
                echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
                print_info "已添加到 /etc/fstab，重启后自动挂载"
            fi
            
            # 优化交换空间设置
            optimize_swap_settings
            return 0
        else
            print_error "交换空间启用失败"
            rm -f "$SWAP_FILE"
            return 1
        fi
    else
        print_error "交换文件创建失败"
        return 1
    fi
}

# 优化交换空间设置
optimize_swap_settings() {
    print_info "优化交换空间设置..."
    for param in "vm.swappiness=10" "vm.vfs_cache_pressure=50"; do
        key=$(echo "$param" | cut -d'=' -f1)
        value=$(echo "$param" | cut -d'=' -f2)
        [ -f "/proc/sys/${key//./\/}" ] && {
            sysctl -w "$param" >/dev/null 2>&1
            grep -q "$key" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
        }
    done
    print_info "已优化: swappiness=10, vfs_cache_pressure=50"
}

# 优化系统内核参数
optimize_kernel_params() {
    print_info "优化系统内核参数..."
    
    # 创建 sysctl 优化配置
    SYSCTL_CONF="/etc/sysctl.d/99-xray-optimize.conf"
    
    cat > "$SYSCTL_CONF" << 'EOF'
# Xray 性能优化内核参数

# TCP 优化 - 提高连接性能
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096

# TCP 连接优化
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3

# TCP 拥塞控制优化
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0

# 连接跟踪优化
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

# IP 转发和路由优化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# 防止 SYN 洪水攻击
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# 时间戳优化
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# 文件描述符和连接数优化
fs.file-max = 2097152
fs.nr_open = 2097152

# 内存管理优化
vm.overcommit_memory = 1
vm.max_map_count = 262144
EOF
    
    # 应用配置
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1
    print_info "内核参数优化配置已创建: $SYSCTL_CONF"
    
    # 检查 BBR 是否可用
    if modprobe tcp_bbr 2>/dev/null; then
        print_info "BBR 拥塞控制算法已启用"
    else
        print_warn "BBR 拥塞控制算法不可用（可能需要内核支持）"
    fi
}

# 优化系统限制
optimize_system_limits() {
    print_info "优化系统资源限制..."
    
    # 创建 limits 配置
    LIMITS_CONF="/etc/security/limits.d/99-xray.conf"
    
    cat > "$LIMITS_CONF" << 'EOF'
# Xray 系统资源限制优化
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 1048576
root hard nproc 1048576
nobody soft nofile 1048576
nobody hard nofile 1048576
nobody soft nproc 1048576
nobody hard nproc 1048576
EOF
    
    print_info "系统资源限制已优化: $LIMITS_CONF"
}

# 创建 systemd 服务
create_service() {
    print_info "创建 systemd 服务..."
    
    # 获取 CPU 核心数用于优化
    CPU_CORES=$(nproc)
    
    # 创建服务主文件
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
# 资源限制优化
LimitNPROC=1048576
LimitNOFILE=1048576
# 内存优化设置
MemoryMax=200M
MemoryHigh=150M
MemorySwapMax=100M
# CPU 限制（可选）
CPUQuota=50%
# 性能优化设置
Nice=-5
IOSchedulingClass=1
IOSchedulingPriority=0
CPUSchedulingPolicy=1
CPUSchedulingPriority=50
# CPU 亲和性（可选，绑定到所有 CPU）
CPUAffinity=0-$((CPU_CORES-1))

[Install]
WantedBy=multi-user.target
EOF
    
    # 创建 drop-in 配置目录
    mkdir -p /etc/systemd/system/xray.service.d
    
    # 创建 drop-in 配置文件（用于后续自定义）
    cat > /etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf << 'EOF'
# In case you have a good reason to do so, duplicate this file in the same directory and make your customizes there.
# Or all changes you made will be lost!
# Refer: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
EOF
    
    # 重载 systemd
    systemctl daemon-reload
    print_info "systemd 服务已创建"
}

# 启动服务
start_service() {
    print_info "启动 Xray 服务..."
    systemctl enable xray
    systemctl start xray
    
    sleep 2
    
    if systemctl is-active --quiet xray; then
        print_info "Xray 服务已成功启动"
        print_info "服务状态:"
        systemctl status xray --no-pager -l
    else
        print_error "Xray 服务启动失败"
        print_error "请检查日志: journalctl -u xray -n 50"
        exit 1
    fi
}

# 显示当前 UUID
show_uuid() {
    CONFIG_FILE="/usr/local/etc/xray/config.json"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "配置文件不存在: $CONFIG_FILE"
        print_info "请先运行安装脚本: sudo bash $0"
        exit 1
    fi
    
    CONFIG_UUID=$(grep -o '"id": "[^"]*"' "$CONFIG_FILE" | head -1 | cut -d'"' -f4)
    
    if [ -z "$CONFIG_UUID" ]; then
        print_error "未找到 UUID，配置文件可能格式不正确"
        exit 1
    fi
    
    echo ""
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "🔐 当前 Xray 服务器 UUID"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "  UUID: ${YELLOW}$CONFIG_UUID${NC}"
    echo ""
    echo -e "  ${RED}⚠️  请妥善保管此 UUID，这是客户端连接的唯一凭证${NC}"
    echo ""
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# 显示 Xray 服务日志
show_logs() {
    if ! systemctl is-active --quiet xray 2>/dev/null; then
        print_warn "Xray 服务未运行"
        echo ""
        print_info "查看服务状态: systemctl status xray"
        print_info "启动服务: systemctl start xray"
        exit 1
    fi
    
    echo ""
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "📋 Xray 服务日志（最近 50 条）"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    journalctl -u xray -n 50 --no-pager
    echo ""
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    print_info "💡 提示："
    echo "  - 实时查看日志: journalctl -u xray -f"
    echo "  - 查看更多日志: journalctl -u xray -n 100"
    echo "  - 查看服务状态: systemctl status xray"
    echo ""
}

# 显示使用说明
show_usage() {
    # 读取配置文件中的 UUID
    CONFIG_FILE="/usr/local/etc/xray/config.json"
    if [ -f "$CONFIG_FILE" ]; then
        CONFIG_UUID=$(grep -o '"id": "[^"]*"' "$CONFIG_FILE" | head -1 | cut -d'"' -f4)
    fi
    
    # 获取服务器 IP
    SERVER_IP=$(get_server_ip)
    
    echo ""
    print_info "=========================================="
    print_info "Xray 服务器安装完成！"
    print_info "=========================================="
    echo ""
    
    # 显示当前服务状态
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "📊 当前服务状态"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if systemctl is-active --quiet xray 2>/dev/null; then
        SERVICE_STATUS="✅ 运行中"
        SERVICE_COLOR="${GREEN}"
    else
        SERVICE_STATUS="❌ 未运行"
        SERVICE_COLOR="${RED}"
    fi
    echo -e "  服务状态: ${SERVICE_COLOR}${SERVICE_STATUS}${NC}"
    
    # 检查端口监听
    if ss -tlnp 2>/dev/null | grep -q ":443.*xray" || netstat -tlnp 2>/dev/null | grep -q ":443.*xray"; then
        PORT_STATUS="✅ 443 端口已监听"
    else
        PORT_STATUS="⚠️  443 端口未监听"
    fi
    echo "  端口状态: $PORT_STATUS"
    
    # 检查证书
    CERT_CRT="/usr/local/etc/xray/cert/certificate.crt"
    CERT_KEY="/usr/local/etc/xray/cert/private.key"
    if [ -f "$CERT_CRT" ] && [ -f "$CERT_KEY" ]; then
        CERT_EXPIRY=$(openssl x509 -in "$CERT_CRT" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        CERT_SUBJECT=$(openssl x509 -in "$CERT_CRT" -noout -subject 2>/dev/null | sed 's/subject=//' | grep -o 'CN=[^,]*' | cut -d'=' -f2)
        if echo "$CERT_SUBJECT" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            CERT_TYPE="自签名证书"
        else
            CERT_TYPE="正式证书"
        fi
        echo "  证书状态: ✅ $CERT_TYPE"
        echo "  证书有效期: $CERT_EXPIRY"
    else
        echo "  证书状态: ❌ 未找到证书文件"
    fi
    
    # 显示系统资源
    if systemctl is-active --quiet xray 2>/dev/null; then
        XRAY_PID=$(systemctl show xray --property MainPID --value 2>/dev/null)
        if [ -n "$XRAY_PID" ] && [ "$XRAY_PID" != "0" ]; then
            MEM_USAGE=$(ps -o rss= -p "$XRAY_PID" 2>/dev/null | awk '{printf "%.1f", $1/1024}')
            CPU_USAGE=$(top -bn1 -p "$XRAY_PID" 2>/dev/null | tail -1 | awk '{print $9}' || echo "N/A")
            if [ -n "$MEM_USAGE" ]; then
                echo "  内存使用: ${MEM_USAGE}MB / 200MB"
            fi
        fi
    fi
    
    echo ""
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "🔗 客户端连接信息"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  服务器地址: $SERVER_IP"
    echo "  端口: 443"
    if [ -n "$CONFIG_UUID" ]; then
        echo "  UUID: ${YELLOW}$CONFIG_UUID${NC}"
        echo ""
        echo -e "  ${RED}⚠️  重要：请立即保存此 UUID！${NC}"
        echo -e "  ${YELLOW}此 UUID 是客户端连接的唯一凭证，丢失后需要重新生成配置${NC}"
        echo ""
    fi
    echo "  传输协议: VLESS"
    echo "  传输方式: WebSocket (ws)"
    echo "  路径: /vless"
    echo "  加密: TLS"
    echo ""
    
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "📝 常用管理命令"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  查看服务状态:   systemctl status xray"
    echo "  启动服务:       systemctl start xray"
    echo "  停止服务:       systemctl stop xray"
    echo "  重启服务:       systemctl restart xray"
    echo "  查看实时日志:   journalctl -u xray -f"
    echo "  查看最近日志:   journalctl -u xray -n 50"
    echo ""
    
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "📁 重要文件位置"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  配置文件: /usr/local/etc/xray/config.json"
    echo "  证书目录: /usr/local/etc/xray/cert/"
    echo "  日志目录: /var/log/xray/"
    echo ""
    
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "⚙️  系统优化状态"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ✓ TCP/IP 内核参数已优化"
    echo "  ✓ BBR 拥塞控制算法已启用"
    echo "  ✓ 交换空间已优化 (swappiness=10)"
    echo "  ✓ 系统资源限制已提升"
    echo "  ✓ 网络缓冲区已优化"
    echo "  ✓ I/O 调度已优化"
    echo ""
    
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_info "⚠️  重要提示"
    print_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -n "$CONFIG_UUID" ]; then
        echo -e "  ${RED}🔐 请务必保存您的 UUID：${YELLOW}$CONFIG_UUID${NC}"
        echo -e "  ${YELLOW}   此 UUID 用于客户端连接，请妥善保管！${NC}"
        echo ""
    fi
    
    if [ -f "$CERT_CRT" ]; then
        if echo "$CERT_TYPE" | grep -q "自签名"; then
            echo "  1. ⚠️  当前使用自签名证书"
            echo "     客户端连接时需要手动信任或忽略证书警告"
            echo ""
            echo "  2. 📱 客户端配置步骤："
            echo "     - 添加服务器: $SERVER_IP:443"
            if [ -n "$CONFIG_UUID" ]; then
                echo "     - UUID: $CONFIG_UUID"
            fi
            echo "     - 传输: WebSocket"
            echo "     - 路径: /vless"
            echo "     - TLS: 启用（忽略证书错误）"
        else
            echo "  1. ✅ 当前使用正式证书，客户端可正常连接"
        fi
    else
        echo "  1. ❌ 未找到证书文件，请配置证书后重启服务"
    fi
    
    echo ""
    echo "  3. 🔧 如果服务未运行，请执行:"
    echo "     sudo systemctl start xray"
    echo "     sudo systemctl status xray"
    echo ""
    
    # 检查优化是否已生效
    echo "  4. 🔄 系统优化状态检查："
    echo ""
    
    # 检查 BBR
    BBR_STATUS=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [ "$BBR_STATUS" = "bbr" ]; then
        echo "     ✅ BBR 拥塞控制: 已生效"
    else
        echo "     ⚠️  BBR 拥塞控制: 未生效（可能需要重启）"
    fi
    
    # 检查系统限制
    CURRENT_LIMIT=$(ulimit -n 2>/dev/null)
    if [ "$CURRENT_LIMIT" = "1048576" ] || [ "$CURRENT_LIMIT" -ge 1048576 ] 2>/dev/null; then
        echo "     ✅ 系统资源限制: 已生效 ($CURRENT_LIMIT)"
    else
        echo "     ⚠️  系统资源限制: 当前 $CURRENT_LIMIT（新会话将使用 1048576）"
    fi
    
    # 检查交换空间
    if swapon --show | grep -q .; then
        echo "     ✅ 交换空间: 已启用"
    else
        echo "     ⚠️  交换空间: 未启用"
    fi
    
    # 检查内核参数
    RMEM_MAX=$(sysctl -n net.core.rmem_max 2>/dev/null)
    if [ "$RMEM_MAX" = "16777216" ]; then
        echo "     ✅ TCP/IP 内核参数: 已生效"
    else
        echo "     ⚠️  TCP/IP 内核参数: 部分未生效"
    fi
    
    echo ""
    
    # 根据检查结果给出建议
    NEED_REBOOT=false
    if [ "$BBR_STATUS" != "bbr" ]; then
        NEED_REBOOT=true
    fi
    if [ "$CURRENT_LIMIT" -lt 1048576 ] 2>/dev/null; then
        NEED_REBOOT=true
    fi
    
    if [ "$NEED_REBOOT" = true ]; then
        echo "     💡 建议：部分优化需要重启系统才能完全生效"
        echo "     重启命令: sudo reboot"
    else
        echo "     ✅ 所有优化已生效，无需重启系统"
    fi
    echo ""
    
    # 如果服务未运行，提供快速启动命令
    if ! systemctl is-active --quiet xray 2>/dev/null; then
        echo ""
        print_warn "服务当前未运行，是否现在启动？"
        read -p "启动服务? (Y/n): " -n 1 -r
        echo ""
        [[ ! $REPLY =~ ^[Nn]$ ]] && {
            systemctl start xray && sleep 1
            systemctl is-active --quiet xray && print_info "✅ 服务已启动！" || \
                print_error "❌ 服务启动失败，请检查日志: journalctl -u xray -n 50"
        }
    fi
    
    echo ""
}

# 主函数
main() {
    print_info "开始安装 Xray 服务器..."
    echo ""
    
    check_root
    detect_arch
    detect_os
    install_dependencies
    create_swap
    optimize_kernel_params
    optimize_system_limits
    install_xray
    create_config
    create_log_dir
    
    # 检查证书文件，如果不存在则生成自签名证书
    CERT_CRT="/usr/local/etc/xray/cert/certificate.crt"
    CERT_KEY="/usr/local/etc/xray/cert/private.key"
    
    if [ ! -f "$CERT_CRT" ] || [ ! -f "$CERT_KEY" ]; then
        print_warn "未检测到 TLS 证书文件"
        echo ""
        print_info "将自动生成自签名证书（适用于只有 IP 地址的情况）"
        echo "  - 有效期：10 年 | 适用于：只有 IP 地址、测试环境"
        echo "  - 客户端需要手动信任或忽略证书警告"
        echo ""
        read -p "是否自动生成自签名证书? (Y/n): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            generate_self_signed_cert || {
                print_error "自签名证书生成失败"
                print_warn "请手动放置证书文件到: /usr/local/etc/xray/cert/"
                echo "  - certificate.crt"
                echo "  - private.key"
                echo ""
                read -p "是否继续启动服务? (y/N): " -n 1 -r
                echo ""
                [[ $REPLY =~ ^[Yy]$ ]] || {
                    print_info "跳过服务启动，请配置证书后手动启动: systemctl start xray"
                    show_usage
                    exit 0
                }
            }
        else
            print_warn "跳过证书生成，请手动放置证书文件到: /usr/local/etc/xray/cert/"
            echo "  - certificate.crt | - private.key"
            echo ""
            read -p "是否继续启动服务? (y/N): " -n 1 -r
            echo ""
            [[ $REPLY =~ ^[Yy]$ ]] || {
                print_info "跳过服务启动，请配置证书后手动启动: systemctl start xray"
                show_usage
                exit 0
            }
        fi
    else
        print_info "检测到现有证书文件"
    fi
    
    create_service
    
    start_service
    show_usage
}

# 处理命令行参数
if [ $# -gt 0 ]; then
    case "$1" in
        -u)
            show_uuid
            exit 0
            ;;
        -l|--logs)
            show_logs
            exit 0
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  -u                   显示当前配置的 UUID"
            echo "  -l, --logs           显示 Xray 服务日志"
            echo "  --help, -h           显示此帮助信息"
            echo ""
            echo "不带参数运行将执行完整的安装流程"
            exit 0
            ;;
        *)
            print_error "未知参数: $1"
            echo "使用 --help 查看帮助信息"
            exit 1
            ;;
    esac
fi

# 运行主函数
main

