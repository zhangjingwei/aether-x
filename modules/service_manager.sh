#!/bin/bash

# 服务管理器模块
# 专门负责生成和管理 Xray systemd 服务配置
# 使用 nobody 用户运行，包含资源限制

# 颜色定义（如果未定义）
if [ -z "${RED}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
fi

# 打印函数（如果未定义）
if ! declare -f print_info >/dev/null; then
    print_info() {
        echo -e "${GREEN}[INFO]${NC} $1"
    }
    print_warn() {
        echo -e "${YELLOW}[WARN]${NC} $1"
    }
    print_error() {
        echo -e "${RED}[ERROR]${NC} $1"
    }
    print_success() {
        echo -e "${GREEN}[SUCCESS]${NC} $1"
    }
fi

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "此操作需要 root 权限"
        return 1
    fi
    return 0
}

# 创建 systemd 服务文件
create_xray_service() {
    local config_path=${1:-"/usr/local/etc/xray/config.json"}
    local memory_limit=${2:-"200M"}
    local cpu_quota=${3:-"50%"}
    
    print_info "创建 Xray systemd 服务..."
    
    # 检查 root 权限
    if ! check_root; then
        return 1
    fi
    
    # 检查 Xray 二进制文件是否存在
    if [ ! -f "/usr/local/bin/xray" ]; then
        print_error "Xray 二进制文件不存在: /usr/local/bin/xray"
        print_error "请先安装 Xray"
        return 1
    fi
    
    # 获取 CPU 核心数
    local cpu_cores=$(nproc)
    
    # 创建主服务文件
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls/Xray-core
After=network.target nss-lookup.target

[Service]
# 用户和权限
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# 执行命令
ExecStart=/usr/local/bin/xray run -config ${config_path}
ExecReload=/bin/kill -HUP \$MAINPID

# 重启策略
Restart=on-failure
RestartSec=5s
RestartPreventExitStatus=23

# 资源限制
LimitNPROC=1048576
LimitNOFILE=1048576
MemoryLimit=${memory_limit}
MemoryHigh=$(( $(echo ${memory_limit} | sed 's/[^0-9]//g') * 9 / 10 ))M
MemorySwapMax=0

# CPU 限制
CPUQuota=${cpu_quota}
CPUWeight=100

# 进程限制
TasksMax=4096

# 性能优化
Nice=-5
IOSchedulingClass=1
IOSchedulingPriority=0
CPUSchedulingPolicy=1
CPUSchedulingPriority=50

# CPU 亲和性（绑定到所有 CPU 核心）
CPUAffinity=0-$((cpu_cores - 1))

# 安全设置
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/xray /usr/local/etc/xray
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
RestrictSUIDSGID=true
RemoveIPC=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # 创建 drop-in 配置目录（用于后续自定义）
    mkdir -p /etc/systemd/system/xray.service.d
    
    # 创建 drop-in 配置文件（保留用于自定义）
    cat > /etc/systemd/system/xray.service.d/10-override.conf << 'EOF'
# X-Ray-Ops 服务覆盖配置
# 如需自定义，请复制此文件并修改，不要直接编辑主服务文件
# 参考: https://www.freedesktop.org/software/systemd/man/systemd.unit.html

[Service]
# 可以在这里覆盖主服务文件的配置
# 例如：
# ExecStart=
# ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
EOF

    # 重载 systemd
    if systemctl daemon-reload; then
        print_success "systemd 服务已创建"
        print_info "配置文件: /etc/systemd/system/xray.service"
        print_info "配置路径: $config_path"
        print_info "内存限制: $memory_limit"
        print_info "CPU 限制: $cpu_quota"
        return 0
    else
        print_error "systemd daemon-reload 失败"
        return 1
    fi
}

# 启用 Xray 服务
enable_xray_service() {
    print_info "启用 Xray 服务..."
    
    if ! check_root; then
        return 1
    fi
    
    if systemctl enable xray >/dev/null 2>&1; then
        print_success "Xray 服务已启用（开机自启）"
        return 0
    else
        print_error "启用 Xray 服务失败"
        return 1
    fi
}

# 启动 Xray 服务
start_xray_service() {
    print_info "启动 Xray 服务..."
    
    if ! check_root; then
        return 1
    fi
    
    # 检查服务文件是否存在
    if [ ! -f "/etc/systemd/system/xray.service" ]; then
        print_error "Xray 服务文件不存在，请先创建服务"
        return 1
    fi
    
    # 强制检查配置文件是否存在（必须拦截）
    local config_path=$(grep "ExecStart.*-config" /etc/systemd/system/xray.service | \
        sed 's/.*-config[[:space:]]*\([^[:space:]]*\).*/\1/' | head -1)
    
    # 如果无法从服务文件中提取配置路径，使用默认路径
    if [ -z "$config_path" ]; then
        config_path="/usr/local/etc/xray/config.json"
    fi
    
    # 绝对拦截：配置文件不存在时不允许启动
    if [ ! -f "$config_path" ]; then
        print_error "配置文件不存在: $config_path"
        print_error "服务已注册但未启动，等待配置文件上传中..."
        print_error "配置文件创建后，请运行: systemctl start xray"
        return 1
    fi
    
    # 启动服务
    if systemctl start xray; then
        sleep 2
        
        if systemctl is-active --quiet xray; then
            print_success "Xray 服务已成功启动"
            return 0
        else
            print_error "Xray 服务启动失败"
            print_error "请检查日志: journalctl -u xray -n 50"
            return 1
        fi
    else
        print_error "启动 Xray 服务失败"
        return 1
    fi
}

# 停止 Xray 服务
stop_xray_service() {
    print_info "停止 Xray 服务..."
    
    if ! check_root; then
        return 1
    fi
    
    if systemctl stop xray; then
        print_success "Xray 服务已停止"
        return 0
    else
        print_warn "停止 Xray 服务失败（可能服务未运行）"
        return 1
    fi
}

# 重启 Xray 服务
restart_xray_service() {
    print_info "重启 Xray 服务..."
    
    if ! check_root; then
        return 1
    fi
    
    if systemctl restart xray; then
        sleep 2
        
        if systemctl is-active --quiet xray; then
            print_success "Xray 服务已成功重启"
            return 0
        else
            print_error "Xray 服务重启失败"
            print_error "请检查日志: journalctl -u xray -n 50"
            return 1
        fi
    else
        print_error "重启 Xray 服务失败"
        return 1
    fi
}

# 禁用 Xray 服务
disable_xray_service() {
    print_info "禁用 Xray 服务..."
    
    if ! check_root; then
        return 1
    fi
    
    if systemctl disable xray >/dev/null 2>&1; then
        print_success "Xray 服务已禁用（不会开机自启）"
        return 0
    else
        print_warn "禁用 Xray 服务失败（可能服务未启用）"
        return 1
    fi
}

# 检查服务状态
check_service_status() {
    if systemctl is-active --quiet xray 2>/dev/null; then
        return 0  # 运行中
    elif systemctl is-enabled --quiet xray 2>/dev/null; then
        return 1  # 已启用但未运行
    else
        return 2  # 未启用
    fi
}

# 获取服务状态信息
get_service_status() {
    local status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
    local enabled=$(systemctl is-enabled xray 2>/dev/null || echo "disabled")
    
    echo "status:$status|enabled:$enabled"
}

# 显示服务状态
show_service_status() {
    print_info "Xray 服务状态:"
    
    if check_service_status; then
        print_success "服务运行中"
        systemctl status xray --no-pager -l | head -20
    else
        local status_info=$(get_service_status)
        local status=$(echo "$status_info" | grep -o "status:[^|]*" | cut -d: -f2)
        local enabled=$(echo "$status_info" | grep -o "enabled:[^|]*" | cut -d: -f2)
        
        if [ "$status" = "inactive" ]; then
            print_warn "服务未运行"
            if [ "$enabled" = "enabled" ]; then
                print_info "服务已启用，但未运行。尝试启动: systemctl start xray"
            fi
        else
            print_error "服务状态异常: $status"
        fi
    fi
}

# 重新加载服务配置（不重启服务）
reload_service_config() {
    print_info "重新加载服务配置..."
    
    if ! check_root; then
        return 1
    fi
    
    if systemctl daemon-reload; then
        print_success "服务配置已重新加载"
        return 0
    else
        print_error "重新加载服务配置失败"
        return 1
    fi
}

# 主函数：创建并启动服务
setup_xray_service() {
    local config_path=${1:-"/usr/local/etc/xray/config.json"}
    local memory_limit=${2:-"200M"}
    local cpu_quota=${3:-"50%"}
    local auto_start=${4:-false}  # 默认不自动启动，等待配置文件部署
    
    print_info "=========================================="
    print_info "设置 Xray 服务"
    print_info "=========================================="
    
    # 创建服务
    if ! create_xray_service "$config_path" "$memory_limit" "$cpu_quota"; then
        return 1
    fi
    
    # 启用服务（开机自启）
    if ! enable_xray_service; then
        return 1
    fi
    
    # 立即清除旧的 failed 状态（如果有）
    systemctl reset-failed xray >/dev/null 2>&1 || true
    
    # 如果指定自动启动，则启动服务
    if [ "$auto_start" = "true" ]; then
        if ! start_xray_service; then
            print_warn "服务创建成功，但启动失败"
            print_info "请检查配置文件: $config_path"
            print_info "查看日志: journalctl -u xray -n 50"
            return 1
        fi
    else
        print_info "服务已注册并启用，但未启动"
        print_info "服务已注册但未启动，等待配置文件上传中..."
        print_info "配置文件部署后，请运行: systemctl start xray"
    fi
    
    print_info "=========================================="
    print_success "Xray 服务设置完成！"
    print_info "=========================================="
    
    return 0
}

# 如果脚本被直接执行（而非被 source），运行设置
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    setup_xray_service
fi
