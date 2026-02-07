#!/bin/bash

# 远程卸载模块
# 用于在远程服务器上卸载 Xray 并清理相关配置

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

# 主函数：卸载 Xray
uninstall_xray() {
    print_info "=========================================="
    print_info "开始卸载 Xray-core"
    print_info "=========================================="
    
    # 检查 root 权限
    if ! check_root; then
        return 1
    fi
    
    local errors=0
    
    # 1. 停止并禁用 Xray 服务
    if systemctl is-active --quiet xray 2>/dev/null; then
        print_info "停止 Xray 服务..."
        if systemctl stop xray 2>/dev/null; then
            print_success "Xray 服务已停止"
        else
            print_warn "停止 Xray 服务失败"
            ((errors++))
        fi
    else
        print_info "Xray 服务未运行"
    fi
    
    if systemctl is-enabled --quiet xray 2>/dev/null; then
        print_info "禁用 Xray 服务..."
        if systemctl disable xray >/dev/null 2>&1; then
            print_success "Xray 服务已禁用"
        else
            print_warn "禁用 Xray 服务失败"
            ((errors++))
        fi
    else
        print_info "Xray 服务未启用"
    fi
    
    # 2. 删除 Xray 二进制文件
    if [ -f "/usr/local/bin/xray" ]; then
        print_info "删除 Xray 二进制文件..."
        if rm -f /usr/local/bin/xray 2>/dev/null; then
            print_success "Xray 二进制文件已删除"
        else
            print_warn "删除 Xray 二进制文件失败"
            ((errors++))
        fi
    else
        print_info "Xray 二进制文件不存在"
    fi
    
    # 3. 删除 systemd 服务文件
    if [ -f "/etc/systemd/system/xray.service" ]; then
        print_info "删除 systemd 服务文件..."
        if rm -f /etc/systemd/system/xray.service 2>/dev/null; then
            print_success "systemd 服务文件已删除"
        else
            print_warn "删除 systemd 服务文件失败"
            ((errors++))
        fi
    else
        print_info "systemd 服务文件不存在"
    fi
    
    # 删除 systemd override 目录（如果存在）
    if [ -d "/etc/systemd/system/xray.service.d" ]; then
        print_info "删除 systemd override 目录..."
        rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true
    fi
    
    # 4. 删除配置文件目录
    if [ -d "/usr/local/etc/xray" ]; then
        print_info "删除配置文件目录..."
        if rm -rf /usr/local/etc/xray 2>/dev/null; then
            print_success "配置文件目录已删除"
        else
            print_warn "删除配置文件目录失败"
            ((errors++))
        fi
    else
        print_info "配置文件目录不存在"
    fi
    
    # 5. 删除日志目录
    if [ -d "/var/log/xray" ]; then
        print_info "删除日志目录..."
        if rm -rf /var/log/xray 2>/dev/null; then
            print_success "日志目录已删除"
        else
            print_warn "删除日志目录失败"
            ((errors++))
        fi
    else
        print_info "日志目录不存在"
    fi
    
    # 6. 重新加载 systemd
    print_info "重新加载 systemd..."
    if systemctl daemon-reload >/dev/null 2>&1; then
        print_success "systemd 已重新加载"
    else
        print_warn "重新加载 systemd 失败"
        ((errors++))
    fi
    
    # 7. 清理 sysctl 配置（可选，保留系统优化配置）
    # 不删除 sysctl 配置，因为可能还有其他服务使用
    
    print_info "=========================================="
    if [ $errors -eq 0 ]; then
        print_success "Xray-core 卸载完成！"
        return 0
    else
        print_warn "Xray-core 卸载完成，但有 $errors 个操作失败"
        return 1
    fi
}

# 如果脚本被直接执行（而非被 source），运行卸载
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    uninstall_xray
fi
