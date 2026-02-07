#!/bin/bash

# 系统优化器模块
# 自动开启 BBR、优化系统参数、创建 Swap、配置资源限制

# 颜色定义（如果未定义）
if [ -z "${RED}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
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
        print_error "此脚本需要 root 权限运行"
        return 1
    fi
    return 0
}

# 检查 BBR 是否已启用
check_bbr_enabled() {
    local bbr_enabled=false
    
    # 检查内核模块是否加载
    if lsmod | grep -q "^tcp_bbr"; then
        bbr_enabled=true
    fi
    
    # 检查 sysctl 配置
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "")
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    
    if [ "$current_qdisc" = "fq" ] && [ "$current_cc" = "bbr" ]; then
        bbr_enabled=true
    fi
    
    if [ "$bbr_enabled" = true ]; then
        return 0
    else
        return 1
    fi
}

# 启用 BBR（幂等性）
enable_bbr() {
    print_info "检查 BBR 状态..."
    
    if check_bbr_enabled; then
        print_success "BBR 已启用，跳过配置"
        return 0
    fi
    
    print_info "正在启用 BBR..."
    
    # 检查内核版本（BBR 需要 4.9+）
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)
    
    if [ "$major" -lt 4 ] || ([ "$major" -eq 4 ] && [ "$minor" -lt 9 ]); then
        print_warn "内核版本 $kernel_version 不支持 BBR（需要 4.9+）"
        return 1
    fi
    
    # 加载 BBR 模块
    if ! lsmod | grep -q "^tcp_bbr"; then
        if modprobe tcp_bbr 2>/dev/null; then
            print_info "BBR 内核模块已加载"
        else
            print_error "加载 BBR 内核模块失败"
            return 1
        fi
    fi
    
    # 加载 fq 队列
    if ! lsmod | grep -q "^sch_fq"; then
        modprobe sch_fq 2>/dev/null || true
    fi
    
    # 配置 sysctl（幂等性：检查是否已存在）
    local sysctl_conf="/etc/sysctl.conf"
    local bbr_config_exists=false
    
    if grep -q "net.core.default_qdisc=fq" "$sysctl_conf" 2>/dev/null && \
       grep -q "net.ipv4.tcp_congestion_control=bbr" "$sysctl_conf" 2>/dev/null; then
        bbr_config_exists=true
    fi
    
    if [ "$bbr_config_exists" = false ]; then
        {
            echo ""
            echo "# BBR 配置 - 由 X-Ray-Ops 添加"
            echo "net.core.default_qdisc=fq"
            echo "net.ipv4.tcp_congestion_control=bbr"
        } >> "$sysctl_conf"
        print_info "BBR 配置已添加到 $sysctl_conf"
    fi
    
    # 立即应用配置
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    
    # 验证
    if check_bbr_enabled; then
        print_success "BBR 已成功启用"
        return 0
    else
        print_warn "BBR 配置已添加，但可能需要重启系统才能生效"
        return 1
    fi
}

# 优化 sysctl 配置（幂等性）
optimize_sysctl() {
    print_info "优化 sysctl 配置..."
    
    local sysctl_file="/etc/sysctl.d/99-xray-optimization.conf"
    local config_marker="# X-Ray-Ops 系统优化配置"
    
    # 检查是否已配置
    if [ -f "$sysctl_file" ] && grep -q "$config_marker" "$sysctl_file" 2>/dev/null; then
        print_info "sysctl 优化配置已存在，检查是否需要更新..."
    fi
    
    # 创建/更新配置文件
    cat > "$sysctl_file" << 'EOF'
# X-Ray-Ops 系统优化配置
# 此文件由 X-Ray-Ops 自动生成，请勿手动修改

# TCP 缓冲区优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# TCP 连接数优化
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535

# TCP 快速回收和重用
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_tw_buckets = 2000000

# 连接跟踪表优化
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# 网络缓冲区
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_slow_start_after_idle = 0

# TCP 选项
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# 文件描述符限制
fs.file-max = 1048576
fs.nr_open = 1048576

# 其他优化
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF

    # 应用配置
    if sysctl -p "$sysctl_file" >/dev/null 2>&1; then
        print_success "sysctl 优化配置已应用"
    else
        print_warn "部分 sysctl 参数可能无法应用（需要重启或内核不支持）"
    fi
    
    # 配置 limits.conf（幂等性）
    local limits_file="/etc/security/limits.conf"
    local limits_marker="# X-Ray-Ops 文件描述符限制"
    
    if ! grep -q "$limits_marker" "$limits_file" 2>/dev/null; then
        {
            echo ""
            echo "$limits_marker"
            echo "* soft nofile 1048576"
            echo "* hard nofile 1048576"
            echo "root soft nofile 1048576"
            echo "root hard nofile 1048576"
        } >> "$limits_file"
        print_success "文件描述符限制已配置"
    else
        print_info "文件描述符限制已存在，跳过配置"
    fi
}

# 获取系统内存（MB）
get_memory_mb() {
    if [ -f /proc/meminfo ]; then
        local mem_total_kb=$(grep "^MemTotal:" /proc/meminfo | awk '{print $2}')
        local mem_total_mb=$((mem_total_kb / 1024))
        echo "$mem_total_mb"
    else
        echo "0"
    fi
}

# 检查 Swap 是否存在
check_swap_exists() {
    if [ -f /swapfile ] || swapon -s | grep -q "/swapfile"; then
        return 0
    else
        return 1
    fi
}

# 创建 Swap 文件（幂等性）
create_swap() {
    print_info "检查 Swap 配置..."
    
    local mem_mb=$(get_memory_mb)
    print_info "当前系统内存: ${mem_mb}MB"
    
    # 如果内存 >= 2GB，不需要创建 Swap
    if [ "$mem_mb" -ge 2048 ]; then
        print_info "系统内存充足（>= 2GB），跳过 Swap 创建"
        return 0
    fi
    
    # 检查是否已存在 Swap
    if check_swap_exists; then
        local swap_size=$(swapon -s | grep "/swapfile" | awk '{print $3}' | head -1)
        print_info "Swap 文件已存在: $swap_size"
        return 0
    fi
    
    # 计算 Swap 大小：内存 < 1GB 创建 2GB，否则创建 1GB
    local swap_size_gb=1
    if [ "$mem_mb" -lt 1024 ]; then
        swap_size_gb=2
    fi
    
    local swap_size_mb=$((swap_size_gb * 1024))
    print_info "正在创建 ${swap_size_gb}GB Swap 文件..."
    
    # 创建 Swap 文件
    if dd if=/dev/zero of=/swapfile bs=1M count=$swap_size_mb status=progress 2>&1; then
        print_info "Swap 文件已创建"
    else
        print_error "创建 Swap 文件失败"
        return 1
    fi
    
    # 设置权限
    if chmod 600 /swapfile; then
        print_info "Swap 文件权限已设置"
    else
        print_error "设置 Swap 文件权限失败"
        rm -f /swapfile
        return 1
    fi
    
    # 格式化为 Swap
    if mkswap /swapfile >/dev/null 2>&1; then
        print_info "Swap 文件已格式化"
    else
        print_error "格式化 Swap 文件失败"
        rm -f /swapfile
        return 1
    fi
    
    # 启用 Swap
    if swapon /swapfile; then
        print_success "Swap 已启用"
    else
        print_error "启用 Swap 失败"
        rm -f /swapfile
        return 1
    fi
    
    # 添加到 /etc/fstab（幂等性）
    if ! grep -q "/swapfile" /etc/fstab 2>/dev/null; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        print_info "Swap 已添加到 /etc/fstab，重启后自动挂载"
    fi
}

# 配置 Xray 资源限制（幂等性）
configure_xray_limits() {
    print_info "配置 Xray 资源限制..."
    
    local systemd_dir="/etc/systemd/system"
    local xray_service="$systemd_dir/xray.service"
    local override_dir="$systemd_dir/xray.service.d"
    local override_file="$override_dir/limits.conf"
    
    # 检查 xray.service 是否存在
    if [ ! -f "$xray_service" ] && [ ! -f "$systemd_dir/xray@.service" ]; then
        print_warn "Xray systemd 服务文件不存在，跳过资源限制配置"
        print_info "将在 Xray 安装后自动配置"
        return 0
    fi
    
    # 创建 override 目录
    mkdir -p "$override_dir" 2>/dev/null || {
        print_error "创建 systemd override 目录失败"
        return 1
    }
    
    # 检查是否已配置
    if [ -f "$override_file" ] && grep -q "# X-Ray-Ops 资源限制" "$override_file" 2>/dev/null; then
        print_info "资源限制配置已存在，更新配置..."
    fi
    
    # 创建/更新 override 配置
    cat > "$override_file" << 'EOF'
# X-Ray-Ops 资源限制配置
# 限制 Xray 使用 200MB 内存和 50% CPU

[Service]
# 内存限制：200MB
MemoryLimit=200M
MemoryHigh=180M

# CPU 限制：50% (0.5 CPU = 500m)
CPUQuota=50%
CPUWeight=100

# 其他限制
TasksMax=4096
EOF

    # 重新加载 systemd
    if systemctl daemon-reload >/dev/null 2>&1; then
        print_success "Xray 资源限制已配置"
        print_info "内存限制: 200MB, CPU 限制: 50%"
        
        # 如果 Xray 服务正在运行，重启以应用限制
        if systemctl is-active --quiet xray 2>/dev/null; then
            print_info "重启 Xray 服务以应用资源限制..."
            systemctl restart xray >/dev/null 2>&1 || print_warn "重启 Xray 服务失败"
        fi
    else
        print_error "重新加载 systemd 失败"
        return 1
    fi
}

# 主函数：执行所有优化
run_system_tuning() {
    print_info "=========================================="
    print_info "开始系统优化"
    print_info "=========================================="
    
    # 检查 root 权限
    if ! check_root; then
        return 1
    fi
    
    local errors=0
    
    # 1. 启用 BBR
    if ! enable_bbr; then
        ((errors++))
    fi
    
    # 2. 优化 sysctl
    if ! optimize_sysctl; then
        ((errors++))
    fi
    
    # 3. 创建 Swap
    if ! create_swap; then
        ((errors++))
    fi
    
    # 4. 配置资源限制
    if ! configure_xray_limits; then
        print_warn "资源限制配置失败（可能 Xray 尚未安装）"
    fi
    
    print_info "=========================================="
    if [ $errors -eq 0 ]; then
        print_success "系统优化完成！"
        return 0
    else
        print_warn "系统优化完成，但有 $errors 个操作失败"
        return 1
    fi
}

# 如果脚本被直接执行（而非被 source），运行主函数
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    run_system_tuning
fi
