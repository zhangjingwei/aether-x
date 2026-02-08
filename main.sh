#!/bin/bash

# Aether-X - Xray-core 自动化部署与多机配置分发工具
# 支持 AWS/腾讯云/谷歌云等多种 VPS 环境

# 检测并处理 Windows 换行符（CRLF）
if [ -f "$0" ]; then
    # 尝试读取第一行，如果包含 \r 则报错
    if head -n 1 "$0" | grep -q $'\r'; then
        echo "错误: 检测到 Windows 换行符（CRLF），脚本无法正常运行" >&2
        echo "" >&2
        echo "解决方案:" >&2
        echo "  1. 安装 dos2unix: sudo apt-get install dos2unix" >&2
        echo "  2. 转换文件: dos2unix $0" >&2
        echo "  3. 或使用: sed -i 's/\r$//' $0" >&2
        exit 1
    fi
fi

set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 全局变量：用于清理钩子
GLOBAL_TEMP_DIRS=()
GLOBAL_TEMP_FILES=()
GLOBAL_BACKGROUND_PIDS=()

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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

# DEBUG输出函数（通过环境变量 DEBUG=true 启用）
debug_log() {
    if [ "${DEBUG:-false}" = "true" ]; then
        echo "[DEBUG] $1" >&2
    fi
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_title() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_menu_title() {
    echo -e "${CYAN}"
    echo "╔═════════════════════════════════╗"
    echo "║    Aether-X 运维工具主菜单      ║"
    echo "╚═════════════════════════════════╝"
    echo -e "${NC}"
}

# 清理钩子函数
cleanup() {
    echo ""
    echo -e "${GREEN}[INFO]${NC} 正在清理后台任务和临时文件..."
    
    # 杀掉当前脚本进程组下的所有后台任务
    if [ ${#GLOBAL_BACKGROUND_PIDS[@]} -gt 0 ]; then
        for pid in "${GLOBAL_BACKGROUND_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done
        # 等待进程退出
        sleep 1
        # 强制杀掉仍在运行的进程
        for pid in "${GLOBAL_BACKGROUND_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
    fi
    
    # 杀掉所有后台任务（jobs -p）
    local jobs_pids=$(jobs -p 2>/dev/null || true)
    if [ -n "$jobs_pids" ]; then
        echo "$jobs_pids" | xargs -r kill 2>/dev/null || true
        sleep 1
        echo "$jobs_pids" | xargs -r kill -9 2>/dev/null || true
    fi
    
    # 清理临时目录
    for temp_dir in "${GLOBAL_TEMP_DIRS[@]}"; do
        if [ -n "$temp_dir" ] && [ -d "$temp_dir" ]; then
            rm -rf "$temp_dir" 2>/dev/null || true
        fi
    done
    
    # 清理临时文件
    for temp_file in "${GLOBAL_TEMP_FILES[@]}"; do
        if [ -n "$temp_file" ] && [ -f "$temp_file" ]; then
            rm -f "$temp_file" 2>/dev/null || true
        fi
    done
    
    # 清理 health_checker.sh 可能创建的临时目录
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[INFO]${NC} 清理完成"
    exit 1
}

# 捕获中断信号
trap cleanup SIGINT SIGTERM

# 检测系统架构
detect_architecture() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            echo "amd64"  # 默认使用 amd64
            ;;
    esac
}

# 使用 Python 解析 YAML（备选方案）
parse_yaml_with_python() {
    local yaml_file=$1
    local query=$2
    
    if ! command -v python3 >/dev/null 2>&1; then
        return 1
    fi
    
    # 简单的 Python one-liner 来解析 YAML
    python3 << EOF
import sys
import json
try:
    import yaml
except ImportError:
    # 如果没有 pyyaml，尝试使用简单的字符串解析
    print("null", file=sys.stderr)
    sys.exit(1)

try:
    with open('$yaml_file', 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    if '$query' == '.servers':
        print(json.dumps(data.get('servers', []), ensure_ascii=False))
    elif '$query' == '.servers | length':
        print(len(data.get('servers', [])))
    else:
        # 简单的字段提取
        servers = data.get('servers', [])
        for server in servers:
            print(json.dumps(server, ensure_ascii=False))
except Exception as e:
    print("null", file=sys.stderr)
    sys.exit(1)
EOF
}

# 安装 yq 工具
install_yq() {
    local arch=$(detect_architecture)
    local yq_url="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${arch}"
    local install_path="/usr/local/bin/yq"
    local temp_file="/tmp/yq_${arch}"
    
    print_info "检测到系统架构: $arch"
    print_info "正在下载 yq..."
    
    # 尝试下载
    if command -v wget >/dev/null 2>&1; then
        if wget -q "$yq_url" -O "$temp_file" 2>/dev/null; then
            print_success "下载成功"
        else
            print_error "下载失败，请检查网络连接"
            return 1
        fi
    elif command -v curl >/dev/null 2>&1; then
        if curl -sL "$yq_url" -o "$temp_file" 2>/dev/null; then
            print_success "下载成功"
        else
            print_error "下载失败，请检查网络连接"
            return 1
        fi
    else
        print_error "未找到 wget 或 curl，无法下载 yq"
        return 1
    fi
    
    # 设置执行权限
    chmod +x "$temp_file"
    
    # 验证下载的文件
    if ! "$temp_file" --version >/dev/null 2>&1; then
        print_error "下载的文件无效"
        rm -f "$temp_file"
        return 1
    fi
    
    # 尝试安装到系统目录
    if [ -w "$(dirname "$install_path")" ]; then
        # 有写权限，直接移动
        mv "$temp_file" "$install_path"
        print_success "yq 已安装到 $install_path"
        return 0
    else
        # 需要 sudo 权限
        print_warn "需要 sudo 权限来安装到 $install_path"
        local use_sudo=true
        if [ -t 0 ] && [ -t 1 ]; then
            echo -ne "${YELLOW}是否使用 sudo 安装？[Y/n]: ${NC}"
            read -r confirm
            if [[ "$confirm" =~ ^[Nn]$ ]]; then
                use_sudo=false
            fi
        fi
        
        if [ "$use_sudo" = "true" ]; then
            if sudo mv "$temp_file" "$install_path" 2>/dev/null; then
                sudo chmod +x "$install_path"
                print_success "yq 已安装到 $install_path"
                return 0
            else
                print_error "安装失败，权限不足"
                rm -f "$temp_file"
                return 1
            fi
        else
            # 用户拒绝，尝试安装到用户目录
            local user_bin="$HOME/bin"
            mkdir -p "$user_bin"
            mv "$temp_file" "$user_bin/yq"
            chmod +x "$user_bin/yq"
            
            # 检查 PATH
            if [[ ":$PATH:" != *":$user_bin:"* ]]; then
                print_warn "yq 已安装到 $user_bin/yq"
                print_info "请将以下内容添加到 ~/.bashrc 或 ~/.zshrc:"
                echo "  export PATH=\"\$HOME/bin:\$PATH\""
                echo ""
                print_info "或者运行: export PATH=\"\$HOME/bin:\$PATH\""
                export PATH="$user_bin:$PATH"
            fi
            print_success "yq 已安装到 $user_bin/yq"
            return 0
        fi
    fi
}

# 检测 WSL 环境
detect_wsl() {
    if [ -f /proc/version ] && grep -qi microsoft /proc/version; then
        return 0
    elif [ -n "${WSL_DISTRO_NAME:-}" ] || [ -n "${WSL_INTEROP:-}" ]; then
        return 0
    else
        return 1
    fi
}

# 检查并修复 SSH 密钥权限
check_ssh_key_permissions() {
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    local fixed_count=0
    local warn_count=0
    
    if [ ! -f "$config_file" ]; then
        return 0  # 配置文件不存在，跳过检查
    fi
    
    if ! command -v yq >/dev/null 2>&1; then
        return 0  # yq 不可用，跳过检查
    fi
    
    print_info "检查 SSH 密钥文件权限..."
    
    # 使用 yq 提取所有 ssh_key 字段
    local ssh_keys=$(yq eval '.servers[].ssh_key // ""' "$config_file" 2>/dev/null | grep -v "^null$" | grep -v "^$")
    
    while IFS= read -r ssh_key; do
        [ -z "$ssh_key" ] && continue
        
        # 展开 ~ 路径
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        
        # 跳过空值或相对路径（需要配置文件存在才能检查）
        if [[ "$ssh_key" == "" ]] || [[ "$ssh_key" == "null" ]]; then
            continue
        fi
        
        # 检查文件是否存在
        if [ ! -f "$ssh_key" ]; then
            if [ "${LOG_LEVEL:-info}" = "debug" ]; then
                print_warn "SSH 密钥文件不存在: $ssh_key（将在使用时检查）"
            fi
            continue
        fi
        
        # 检查权限
        local current_perms=$(stat -c "%a" "$ssh_key" 2>/dev/null || stat -f "%OLp" "$ssh_key" 2>/dev/null || echo "")
        
        if [ -z "$current_perms" ]; then
            continue
        fi
        
        # 检查权限是否为 600
        if [ "$current_perms" != "600" ]; then
            print_warn "SSH 密钥权限不正确: $ssh_key (当前: $current_perms, 应为: 600)"
            
            # 尝试自动修复
            if chmod 600 "$ssh_key" 2>/dev/null; then
                print_success "已自动修复权限: $ssh_key"
                ((fixed_count++))
            else
                print_error "无法自动修复权限: $ssh_key"
                print_info "请手动执行: chmod 600 $ssh_key"
                ((warn_count++))
            fi
        fi
    done <<< "$ssh_keys"
    
    if [ $fixed_count -gt 0 ]; then
        print_success "已修复 $fixed_count 个密钥文件权限"
    fi
    
    if [ $warn_count -gt 0 ]; then
        print_warn "有 $warn_count 个密钥文件需要手动修复权限"
    fi
    
    return 0
}

# 检查 SSH 工具链
check_ssh_tools() {
    local missing_tools=()
    
    # 检查 ssh-keygen
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        missing_tools+=("openssh-client (包含 ssh-keygen)")
    fi
    
    # 检查 ssh
    if ! command -v ssh >/dev/null 2>&1; then
        missing_tools+=("openssh-client (包含 ssh)")
    fi
    
    # 检查 scp
    if ! command -v scp >/dev/null 2>&1; then
        missing_tools+=("openssh-client (包含 scp)")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "缺少 SSH 工具: ${missing_tools[*]}"
        print_info "安装命令:"
        echo "  Ubuntu/Debian: sudo apt-get install openssh-client"
        echo "  CentOS/RHEL: sudo yum install openssh-clients"
        echo "  macOS: 通常已预装"
        return 1
    fi
    
    # 设置 SSH 默认选项（通过环境变量）
    export SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}"
    export SCP_OPTS="${SCP_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}"
    
    if [ "${LOG_LEVEL:-info}" = "debug" ]; then
        print_info "SSH 默认选项: $SSH_OPTS"
    fi
    
    return 0
}

# 检查增强工具链
check_enhanced_tools() {
    local missing_tools=()
    local optional_tools=()
    
    # 必需工具
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing_tools+=("curl 或 wget")
    fi
    
    if ! command -v openssl >/dev/null 2>&1; then
        missing_tools+=("openssl")
    fi
    
    # 可选工具（密码登录时需要）
    if ! command -v sshpass >/dev/null 2>&1; then
        optional_tools+=("sshpass (密码登录时需要)")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "缺少必需工具: ${missing_tools[*]}"
        print_info "安装命令:"
        echo "  Ubuntu/Debian: sudo apt-get install curl openssl"
        echo "  CentOS/RHEL: sudo yum install curl openssl"
        return 1
    fi
    
    if [ ${#optional_tools[@]} -gt 0 ]; then
        if [ "${LOG_LEVEL:-info}" = "debug" ]; then
            print_info "可选工具未安装: ${optional_tools[*]}"
            print_info "如需密码登录，请安装: sudo apt-get install sshpass"
        fi
    fi
    
    return 0
}

# WSL 环境特殊检查
check_wsl_environment() {
    if ! detect_wsl; then
        return 0  # 不是 WSL 环境，跳过
    fi
    
    print_info "检测到 WSL 环境，进行特殊检查..."
    
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    if [ ! -f "$config_file" ]; then
        return 0
    fi
    
    if ! command -v yq >/dev/null 2>&1; then
        return 0
    fi
    
    # 检查 Windows 路径中的密钥文件
    local ssh_keys=$(yq eval '.servers[].ssh_key // ""' "$config_file" 2>/dev/null | grep -v "^null$" | grep -v "^$")
    
    while IFS= read -r ssh_key; do
        [ -z "$ssh_key" ] && continue
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        
        # 检查是否是 Windows 路径（/mnt/c, /mnt/d 等）
        if [[ "$ssh_key" =~ ^/mnt/[a-z]/ ]]; then
            if [ -f "$ssh_key" ]; then
                local perms=$(stat -c "%a" "$ssh_key" 2>/dev/null || echo "")
                if [ -n "$perms" ] && [ "$perms" != "600" ]; then
                    print_warn "WSL 环境中的 Windows 文件权限可能无法修改: $ssh_key"
                    print_info "Windows 文件系统权限由 Windows 控制，建议："
                    echo "  1. 将密钥文件移动到 Linux 文件系统: ~/keys/"
                    echo "  2. 或在 Windows 中设置文件属性（右键 -> 属性 -> 安全）"
                fi
            fi
        fi
    done <<< "$ssh_keys"
    
    return 0
}

# 网络预检（ping 检查）
ping_check() {
    local ip=$1
    local timeout=${2:-2}
    
    # 检查 ping 命令是否可用
    if ! command -v ping >/dev/null 2>&1; then
        return 0  # ping 不可用，跳过检查
    fi
    
    # 根据系统类型选择 ping 参数
    local ping_cmd
    if ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
        # Linux 风格
        ping_cmd="ping -c 1 -W $timeout"
    elif ping -c 1 -w 1 127.0.0.1 >/dev/null 2>&1; then
        # macOS/BSD 风格
        ping_cmd="ping -c 1 -W $((timeout * 1000))"
    else
        return 0  # 无法确定，跳过
    fi
    
    # 执行 ping
    if $ping_cmd "$ip" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 批量网络预检
batch_ping_check() {
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    local failed_ips=()
    
    if [ ! -f "$config_file" ]; then
        return 0
    fi
    
    if ! command -v yq >/dev/null 2>&1; then
        return 0  # yq 不可用，跳过
    fi
    
    print_info "执行网络预检（ping 检查）..."
    
    # 提取所有 IP 地址
    local ips=$(yq eval '.servers[].ip // ""' "$config_file" 2>/dev/null | grep -v "^null$" | grep -v "^$" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
    
    if [ -z "$ips" ]; then
        return 0  # 没有 IP 地址，跳过
    fi
    
    local total=0
    local reachable=0
    local unreachable=0
    
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        ((total++))
        
        if ping_check "$ip" 2; then
            ((reachable++))
            if [ "${LOG_LEVEL:-info}" = "debug" ]; then
                print_info "  ✓ $ip 可达"
            fi
        else
            ((unreachable++))
            failed_ips+=("$ip")
            print_warn "  ✗ $ip 不可达（将在 SSH 连接时跳过）"
        fi
    done <<< "$ips"
    
    if [ $total -gt 0 ]; then
        print_info "网络预检完成: $reachable/$total 个 IP 可达"
        if [ $unreachable -gt 0 ]; then
            print_warn "以下 IP 不可达，将在后续操作中跳过:"
            for ip in "${failed_ips[@]}"; do
                echo "  - $ip"
            done
            # 将不可达的 IP 保存到环境变量，供后续模块使用
            export UNREACHABLE_IPS="${failed_ips[*]}"
        fi
    fi
    
    return 0
}

# 检查本地依赖
check_local_deps() {
    # 检查是否在非交互模式（通过环境变量跳过）
    local skip_check="${SKIP_DEP_CHECK:-false}"
    if [ "$skip_check" = "true" ]; then
        return 0
    fi
    
    print_title "检查本地环境依赖"
    
    local check_failed=0
    
    # 0. 检查 YAML 配置文件语法（如果配置文件存在）
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    if [ -f "$config_file" ]; then
        if command -v yq >/dev/null 2>&1; then
            print_info "检查 YAML 配置文件语法..."
            local yaml_errors=$(yq eval '.' "$config_file" >/dev/null 2>&1)
            if [ $? -ne 0 ]; then
                print_error "YAML 配置文件语法错误: $config_file"
                # 尝试获取更详细的错误信息
                if command -v python3 >/dev/null 2>&1; then
                    python3 -c "
import yaml
import sys
try:
    with open('$config_file', 'r', encoding='utf-8') as f:
        yaml.safe_load(f)
except yaml.YAMLError as e:
    if hasattr(e, 'problem_mark'):
        mark = e.problem_mark
        print(f'错误位置: 第 {mark.line + 1} 行, 第 {mark.column + 1} 列')
    print(f'错误信息: {e}')
    sys.exit(1)
" 2>&1 || true
                fi
                print_warn "YAML 语法检查失败，但将继续执行（可能导致解析错误）"
            else
                print_success "YAML 配置文件语法正确"
            fi
        elif command -v python3 >/dev/null 2>&1 && python3 -c "import yaml" 2>/dev/null; then
            # 使用 Python 检查 YAML 语法
            print_info "使用 Python 检查 YAML 配置文件语法..."
            if ! python3 -c "
import yaml
import sys
try:
    with open('$config_file', 'r', encoding='utf-8') as f:
        yaml.safe_load(f)
    print('YAML 语法正确')
except yaml.YAMLError as e:
    if hasattr(e, 'problem_mark'):
        mark = e.problem_mark
        print(f'错误位置: 第 {mark.line + 1} 行, 第 {mark.column + 1} 列', file=sys.stderr)
    print(f'错误信息: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
                print_warn "YAML 语法检查失败，但将继续执行"
            else
                print_success "YAML 配置文件语法正确"
            fi
        fi
    fi
    
    # 1. 检查 yq
    if ! command -v yq >/dev/null 2>&1; then
        print_warn "未检测到 yq 工具"
        
        # 检查是否在交互式终端
        if [ -t 0 ] && [ -t 1 ]; then
            echo ""
            echo -ne "${YELLOW}是否自动安装 yq？[Y/n]: ${NC}"
            read -r install_confirm
            
            if [[ ! "$install_confirm" =~ ^[Nn]$ ]]; then
                if install_yq; then
                    # 验证安装
                    if command -v yq >/dev/null 2>&1; then
                        print_success "yq 安装成功"
                    else
                        ((check_failed++))
                    fi
                else
                    ((check_failed++))
                fi
            else
                ((check_failed++))
            fi
        else
            # 非交互模式，尝试自动安装
            print_info "非交互模式，尝试自动安装 yq..."
            if install_yq; then
                if command -v yq >/dev/null 2>&1; then
                    print_success "yq 安装成功"
                else
                    ((check_failed++))
                fi
            else
                ((check_failed++))
            fi
        fi
        
        # 安装失败或用户拒绝，尝试 Python 备选方案
        if [ $check_failed -gt 0 ]; then
            print_info "尝试使用 Python 作为备选方案..."
            if command -v python3 >/dev/null 2>&1; then
                if python3 -c "import yaml" 2>/dev/null; then
                    print_success "检测到 Python3 和 pyyaml，将使用 Python 解析 YAML"
                    export USE_PYTHON_YAML=true
                    check_failed=0
                else
                    print_warn "Python3 可用，但缺少 pyyaml 模块"
                    print_info "可以运行以下命令安装: pip3 install pyyaml"
                fi
            fi
        fi
        
        if [ $check_failed -gt 0 ]; then
            print_error "无法继续，请安装 yq 或 pyyaml"
            print_info "安装 yq: https://github.com/mikefarah/yq"
            print_info "或设置环境变量 SKIP_DEP_CHECK=true 跳过检查（不推荐）"
            return 1
        fi
    else
        # yq 已安装，验证版本
        if ! yq --version >/dev/null 2>&1; then
            print_warn "yq 命令存在但无法正常运行"
            ((check_failed++))
        fi
    fi
    
    # 2. 检查 SSH 工具链（非阻塞，只警告）
    if ! check_ssh_tools; then
        print_warn "SSH 工具链检查失败，但将继续执行"
        # 不增加 check_failed，因为这是警告
    fi
    
    # 3. 检查增强工具链（非阻塞）
    if ! check_enhanced_tools; then
        print_warn "增强工具链检查失败，部分功能可能不可用"
        # 不增加 check_failed，因为这是警告
    fi
    
    # 4. 检查并修复 SSH 密钥权限（非阻塞）
    check_ssh_key_permissions || print_warn "SSH 密钥权限检查失败，但将继续执行"
    
    # 5. WSL 环境特殊检查（非阻塞）
    check_wsl_environment || print_warn "WSL 环境检查失败，但将继续执行"
    
    # 6. 网络预检（非阻塞，仅提示）
    if [ "${SKIP_PING_CHECK:-false}" != "true" ]; then
        batch_ping_check || print_warn "网络预检失败，但将继续执行"
    fi
    
    echo ""
    if [ $check_failed -eq 0 ]; then
        print_success "环境依赖检查完成"
        return 0
    else
        print_error "环境依赖检查发现问题，请根据上述提示修复"
        return 1
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
Aether-X - Xray-core 自动化部署工具

用法: $0

这是一个交互式工具，运行后会显示菜单，您可以选择：
  [1] 批量部署远程节点 - 选择要部署的服务器
  [2] 检查所有节点在线状态
  [3] 健康检查（TCP/ICMP/应用层检测）
  [4] 生成订阅链接
  [5] 批量卸载远程节点 - 选择要卸载的服务器
  [0] 退出

配置文件: configs/servers.yaml

EOF
}

# 显示交互式菜单
show_menu() {
    clear
    print_menu_title
    
    echo -e "${GREEN}请选择操作:${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} 批量部署远程节点"
    echo -e "  ${CYAN}[2]${NC} 检查所有节点在线状态"
    echo -e "  ${CYAN}[3]${NC} 健康检查（TCP/ICMP/应用层检测）"
    echo -e "  ${CYAN}[4]${NC} 生成订阅链接"
    echo -e "  ${CYAN}[5]${NC} 批量卸载远程节点"
    echo -e "  ${CYAN}[0]${NC} 退出"
    echo ""
    echo -ne "${YELLOW}请输入选项 [0-5]: ${NC}"
}

# 选项1: 批量部署远程节点
menu_batch_deploy() {
    print_title "批量部署远程节点"
    
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    
    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file"
        print_info "请先创建配置文件: $config_file"
        return 1
    fi
    
    # 先加载 multi_server 模块（select_servers 需要它）
    load_module "multi_server"
    
    # 选择服务器
    local selected=$(select_servers "$config_file")
    if [ $? -ne 0 ] || [ -z "$selected" ]; then
        print_info "已取消部署"
        return 0
    fi
    
    # 执行批量部署（传入选中的服务器）
    local selected_array=($selected)
    if [ ${#selected_array[@]} -eq 1 ]; then
        # 单个服务器
        batch_deploy "$config_file" "$SCRIPT_DIR" "${selected_array[0]}"
    else
        # 多个服务器，逐个部署
        for server_alias in "${selected_array[@]}"; do
            echo ""
            print_info "部署服务器: $server_alias"
            batch_deploy "$config_file" "$SCRIPT_DIR" "$server_alias"
        done
    fi
}

# 选项3: 检查所有节点在线状态
menu_check_status() {
    print_title "检查所有节点在线状态"
    
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    
    debug_log "menu_check_status 开始执行"
    debug_log "config_file: $config_file"
    
    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file"
        return 1
    fi
    
    # 加载模块
    load_module "multi_server"
    debug_log "模块加载完成"
    
    # 执行状态检查
    debug_log "准备调用 batch_check_status"
    batch_check_status "$config_file"
    local check_exit=$?
    debug_log "batch_check_status 返回码: $check_exit"
    
    # 确保函数正常返回
    debug_log "menu_check_status 准备返回"
    return 0
}

# 选项4: 健康检查
menu_health_check() {
    print_title "健康检查（TCP/ICMP/应用层检测）"
    
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    
    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file"
        return 1
    fi
    
    # 加载模块
    load_module "health_checker"
    
    # 执行健康检查
    batch_health_check "$config_file" "true" "10"
}

# 选项5: 生成订阅链接
menu_generate_subscription() {
    print_title "生成订阅链接"
    
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    local log_dir="${SCRIPT_DIR}/logs"
    
    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file"
        return 1
    fi
    
    # 加载模块
    load_module "sub_manager"
    
    # 查找可用的健康检查日志
    local check_log=""
    local log_files=()
    
    if [ -d "$log_dir" ]; then
        # 查找所有检查日志文件（按时间倒序）
        while IFS= read -r -d '' file; do
            log_files+=("$file")
        done < <(find "$log_dir" -maxdepth 1 -name "check_*.log" -type f -print0 2>/dev/null | sort -z -r)
        
        # 也检查符号链接
        if [ -L "$log_dir/last_check.log" ]; then
            local linked_file=$(readlink -f "$log_dir/last_check.log" 2>/dev/null)
            if [ -f "$linked_file" ]; then
                check_log="$linked_file"
            fi
        elif [ -f "$log_dir/last_check.log" ]; then
            check_log="$log_dir/last_check.log"
        fi
    fi
    
    # 如果没有找到日志，让用户选择
    if [ -z "$check_log" ] && [ ${#log_files[@]} -eq 0 ]; then
        print_warn "未找到健康检查日志，将使用所有节点"
        echo -ne "${YELLOW}是否继续？[y/N]: ${NC}"
        read -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_info "已取消"
            return 0
        fi
        check_log=""
    elif [ ${#log_files[@]} -gt 1 ]; then
        # 有多个日志文件，让用户选择
        echo ""
        echo -e "${CYAN}发现多个健康检查日志，请选择:${NC}"
        echo "  [0] 使用最新日志（推荐）"
        local idx=1
        for log_file in "${log_files[@]:0:10}"; do
            local file_name=$(basename "$log_file")
            local file_time=$(stat -c "%y" "$log_file" 2>/dev/null | cut -d'.' -f1 || stat -f "%Sm" "$log_file" 2>/dev/null | cut -d'.' -f1 || echo "未知时间")
            echo "  [$idx] $file_name ($file_time)"
            ((idx++))
        done
        echo ""
        echo -ne "${YELLOW}请选择 [0-$((idx-1))]: ${NC}"
        read -r log_choice
        
        if [ "$log_choice" = "0" ]; then
            check_log="${log_files[0]}"
        elif [ "$log_choice" -ge 1 ] && [ "$log_choice" -lt "$idx" ]; then
            check_log="${log_files[$((log_choice-1))]}"
        else
            print_error "无效选择"
            return 1
        fi
    elif [ ${#log_files[@]} -eq 1 ]; then
        # 只有一个日志文件，直接使用
        check_log="${log_files[0]}"
    fi
    
    # 询问是否分发
    echo ""
    echo -e "${CYAN}选择分发方式:${NC}"
    echo "  [1] 仅生成本地文件"
    echo "  [2] 上传到 AWS S3"
    echo "  [3] 上传到 GitHub Pages"
    echo "  [4] 上传到 VPS (Nginx)"
    echo "  [0] 取消"
    echo ""
    echo -ne "${YELLOW}请选择 [0-4]: ${NC}"
    read -r dist_choice
    
    local dist_method=""
    local dist_config=""
    
    case "$dist_choice" in
        1)
            dist_method=""
            ;;
        2)
            echo -ne "${YELLOW}请输入 S3 Bucket (格式: bucket:key): ${NC}"
            read -r dist_config
            dist_method="s3"
            ;;
        3)
            echo -ne "${YELLOW}请输入 GitHub 配置 (格式: owner:repo:token:branch:path): ${NC}"
            read -r dist_config
            dist_method="github"
            ;;
        4)
            echo -ne "${YELLOW}请输入 VPS 配置 (格式: ip:port:user:key:remote_path): ${NC}"
            read -r dist_config
            dist_method="vps"
            ;;
        *)
            print_info "已取消"
            return 0
            ;;
    esac
    
    # 执行生成和分发（如果 check_log 为空，传递空字符串）
    generate_and_distribute_subscription "$config_file" "${check_log:-}" "$dist_method" "$dist_config"
}

# 选项5: 批量卸载远程节点
menu_batch_uninstall() {
    print_title "批量卸载远程节点"
    
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/configs/servers.yaml}"
    
    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file"
        print_info "请先创建配置文件: $config_file"
        return 1
    fi
    
    # 先加载 multi_server 模块（select_servers 需要它）
    load_module "multi_server"
    
    # 选择服务器
    local selected=$(select_servers "$config_file")
    if [ $? -ne 0 ] || [ -z "$selected" ]; then
        print_info "已取消卸载"
        return 0
    fi
    
    echo ""
    echo -e "${RED}警告: 此操作将卸载选中服务器上的 Xray 并清理相关配置${NC}"
    echo ""
    echo -ne "${YELLOW}确认卸载？[y/N]: ${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "已取消卸载"
        return 0
    fi
    
    # 执行批量卸载（传入选中的服务器）
    local selected_array=($selected)
    if [ ${#selected_array[@]} -eq 1 ]; then
        # 单个服务器
        batch_uninstall "$config_file" "$SCRIPT_DIR" "${selected_array[0]}"
    else
        # 多个服务器，逐个卸载
        for server_alias in "${selected_array[@]}"; do
            echo ""
            print_info "卸载服务器: $server_alias"
            batch_uninstall "$config_file" "$SCRIPT_DIR" "$server_alias"
        done
    fi
}

# 加载模块
load_module() {
    local module_name=$1
    if [ -f "$SCRIPT_DIR/modules/$module_name.sh" ]; then
        source "$SCRIPT_DIR/modules/$module_name.sh"
    else
        print_error "模块 $module_name.sh 不存在"
        exit 1
    fi
}

# 选择服务器
select_servers() {
    local config_file=$1
    local selected_servers=()
    
    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file" >&2
        return 1
    fi
    
    # 加载 multi_server 模块以使用 parse_server_config
    if ! declare -f parse_server_config >/dev/null 2>&1; then
        load_module "multi_server"
    fi
    
    # 获取服务器列表（使用 parse_server_config 确保格式一致）
    local servers=$(parse_server_config "$config_file" 2>/dev/null)
    if [ -z "$servers" ]; then
        print_error "未找到服务器配置或解析失败" >&2
        return 1
    fi
    
    local server_list=()
    local index=1
    
    echo "" >&2
    echo -e "${CYAN}服务器列表:${NC}" >&2
    echo "" >&2
    
    # 处理 yq 可能输出的多行 JSON
    # 如果输出是多行 JSON 对象，需要合并为单行
    local servers_processed
    if echo "$servers" | grep -q '^{$'; then
        # 多行 JSON，使用 awk 将每个 JSON 对象合并为单行
        servers_processed=$(echo "$servers" | awk '
            BEGIN { json="" }
            {
                json = json (json ? " " : "") $0
                if ($0 ~ /^}/) {
                    print json
                    json = ""
                }
            }
            END { if (json) print json }
        ')
    else
        # 已经是单行 JSON
        servers_processed="$servers"
    fi
    
    # 使用临时文件确保正确读取所有行
    local temp_file=$(mktemp)
    echo "$servers_processed" > "$temp_file"
    
    while IFS= read -r server_json; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        
        # 使用 extract_server_field 函数（如果已定义）
        local alias=""
        local ip=""
        
        if declare -f extract_server_field >/dev/null 2>&1; then
            alias=$(extract_server_field "$server_json" "alias" 2>/dev/null)
            ip=$(extract_server_field "$server_json" "ip" 2>/dev/null)
        elif command -v jq >/dev/null 2>&1; then
            alias=$(echo "$server_json" | jq -r '.alias // empty' 2>/dev/null)
            ip=$(echo "$server_json" | jq -r '.ip // empty' 2>/dev/null)
        else
            alias=$(echo "$server_json" | grep -o '"alias":"[^"]*"' | cut -d'"' -f4)
            ip=$(echo "$server_json" | grep -o '"ip":"[^"]*"' | cut -d'"' -f4)
        fi
        
        if [ -n "$alias" ] && [ -n "$ip" ]; then
            echo -e "  ${CYAN}[$index]${NC} $alias ($ip)" >&2
            server_list+=("$alias")
            ((index++))
        fi
    done < "$temp_file"
    
    rm -f "$temp_file"
    
    if [ ${#server_list[@]} -eq 0 ]; then
        print_error "未找到任何服务器配置" >&2
        return 1
    fi
    
    echo "" >&2
    echo -e "  ${CYAN}[a]${NC} 选择所有服务器" >&2
    echo -e "  ${CYAN}[0]${NC} 取消" >&2
    echo "" >&2
    echo -ne "${YELLOW}请选择服务器（多个用逗号分隔，如: 1,2,3 或 a 选择全部）: ${NC}" >&2
    read -r selection
    
    if [ -z "$selection" ] || [ "$selection" = "0" ]; then
        return 1
    fi
    
    # 处理选择
    if [ "$selection" = "a" ] || [ "$selection" = "A" ]; then
        selected_servers=("${server_list[@]}")
    else
        # 解析逗号分隔的选择
        IFS=',' read -ra choices <<< "$selection"
        for choice in "${choices[@]}"; do
            choice=$(echo "$choice" | tr -d ' ')
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#server_list[@]} ]; then
                local idx=$((choice - 1))
                selected_servers+=("${server_list[$idx]}")
            fi
        done
    fi
    
    if [ ${#selected_servers[@]} -eq 0 ]; then
        print_error "未选择任何服务器" >&2
        return 1
    fi
    
    # 输出选中的服务器（用空格分隔）- 只输出到 stdout
    echo "${selected_servers[@]}"
    return 0
}

# 主函数
main() {
    # 设置默认配置
    CONFIG_FILE="${SCRIPT_DIR}/configs/servers.yaml"
    
    # 检查依赖
    check_local_deps || {
        print_error "依赖检查失败，无法继续"
        print_info "提示: 可以设置 SKIP_DEP_CHECK=true 跳过检查（不推荐）"
        exit 1
    }

    # 交互式菜单模式
    while true; do
        show_menu
        read -r choice
        echo ""
        
        case $choice in
            1)
                menu_batch_deploy
                echo ""
                echo -ne "${YELLOW}按 Enter 键返回菜单...${NC}"
                read -r
                ;;
            2)
                debug_log "菜单选项2被选择"
                menu_check_status
                local menu_exit=$?
                debug_log "menu_check_status 返回码: $menu_exit"
                echo ""
                echo -ne "${YELLOW}按 Enter 键返回菜单...${NC}"
                debug_log "准备等待用户输入"
                read -r
                debug_log "用户已按回车，准备返回菜单"
                ;;
            3)
                menu_health_check
                echo ""
                echo -ne "${YELLOW}按 Enter 键返回菜单...${NC}"
                read -r
                ;;
            4)
                menu_generate_subscription
                echo ""
                echo -ne "${YELLOW}按 Enter 键返回菜单...${NC}"
                read -r
                ;;
            5)
                menu_batch_uninstall
                echo ""
                echo -ne "${YELLOW}按 Enter 键返回菜单...${NC}"
                read -r
                ;;
            0)
                print_info "再见！"
                exit 0
                ;;
            *)
                print_error "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 运行主函数
main "$@"
