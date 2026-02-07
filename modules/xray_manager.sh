#!/bin/bash

# Xray 管理器模块
# 负责下载、校验、安装 Xray 二进制文件，创建必要的目录结构
# 不包含配置生成、系统优化、服务管理等逻辑

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

# 检测系统架构
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64)
            echo "64"
            ;;
        aarch64|arm64)
            echo "arm64-v8a"
            ;;
        armv7l|armv6l)
            echo "arm32-v7a"
            ;;
        *)
            print_error "不支持的架构: $arch"
            return 1
            ;;
    esac
}

# 获取 Xray 最新版本号
get_latest_version() {
    local version=$(curl -s --max-time 10 \
        "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null | \
        grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' | sed 's/^v//')
    
    if [ -z "$version" ]; then
        print_warn "无法从 GitHub 获取最新版本，使用已知稳定版本: 1.8.4"
        echo "1.8.4"
    else
        echo "$version"
    fi
}

# 计算文件 SHA256 哈希
calculate_sha256() {
    local file=$1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        print_warn "未找到 sha256sum 或 shasum，跳过哈希校验"
        echo ""
    fi
}

# 验证文件哈希（如果提供了预期哈希）
verify_hash() {
    local file=$1
    local expected_hash=$2
    
    if [ -z "$expected_hash" ]; then
        return 0  # 没有提供预期哈希，跳过验证
    fi
    
    local actual_hash=$(calculate_sha256 "$file")
    if [ -z "$actual_hash" ]; then
        print_warn "无法计算文件哈希，跳过验证"
        return 0
    fi
    
    if [ "$actual_hash" = "$expected_hash" ]; then
        print_success "文件哈希验证通过"
        return 0
    else
        print_error "文件哈希验证失败"
        print_error "预期: $expected_hash"
        print_error "实际: $actual_hash"
        return 1
    fi
}

# 检测网络连接（测试是否能访问外部网络）
check_network_connectivity() {
    local test_urls=(
        "https://www.github.com"
        "https://github.com"
        "https://www.google.com"
    )
    
    for url in "${test_urls[@]}"; do
        if command -v wget >/dev/null 2>&1; then
            if wget --spider --timeout=5 --tries=1 "$url" >/dev/null 2>&1; then
                return 0
            fi
        elif command -v curl >/dev/null 2>&1; then
            if curl -s --connect-timeout 5 --max-time 5 "$url" >/dev/null 2>&1; then
                return 0
            fi
        fi
    done
    
    return 1
}

# 获取镜像源下载 URL
get_mirror_urls() {
    local version=$1
    local arch=$2
    
    local urls=(
        # GitHub 官方源（主源）
        "https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
        
        # 清华镜像源（GitHub Release 镜像）
        "https://mirrors.tuna.tsinghua.edu.cn/github-release/XTLS/Xray-core/v${version}/Xray-linux-${arch}.zip"
        
        # ghproxy 镜像（GitHub 代理）
        "https://ghproxy.com/https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
        
        # FastGit 镜像
        "https://download.fastgit.org/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
        
        # GitClone 镜像
        "https://gitclone.com/github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
    )
    
    echo "${urls[@]}"
}

# 快速检测 URL 是否可达（不下载，只检测连接）
quick_check_url() {
    local url=$1
    local timeout=5  # 快速检测，5秒超时
    
    if command -v wget >/dev/null 2>&1; then
        # 使用 wget --spider 快速检测（不下载文件）
        if wget --spider --timeout=$timeout --tries=1 "$url" >/dev/null 2>&1; then
            return 0
        fi
    elif command -v curl >/dev/null 2>&1; then
        # 使用 curl -I 快速检测（只获取头部信息）
        if curl -s -I --connect-timeout $timeout --max-time $timeout -L "$url" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    return 1
}

# 尝试从指定 URL 下载
try_download_from_url() {
    local url=$1
    local output_file=$2
    
    # 先快速检测连接（3秒超时）
    if ! quick_check_url "$url"; then
        return 1  # 连接不可达，立即返回
    fi
    
    # 连接可达，开始下载（使用较短的超时时间）
    if command -v wget >/dev/null 2>&1; then
        # 使用 wget 下载，显示进度
        # 使用 dot:mega 模式，每下载 1MB 显示一个点
        # 这样即使通过管道也能看到进度
        print_info "正在下载（每 MB 显示一个点）..."
        
        # 执行下载，过滤并显示进度信息
        if wget --progress=dot:mega --timeout=15 --tries=1 \
           -O "$output_file" "$url" 2>&1 | \
           grep -v "^Resolving\|^Connecting\|^HTTP\|^Length:\|^Saving to" | \
           grep -E "(\.|saved|MB|KB)" | \
           while IFS= read -r line; do
               # 显示进度点或文件大小信息
               if echo "$line" | grep -qE "\.{10,}"; then
                   # 显示多个点（表示下载进度）
                   local dots=$(echo "$line" | grep -o "\.\{1,\}" | wc -l)
                   printf "下载中%s (%d MB) " "." "$dots"
               elif echo "$line" | grep -qE "saved|MB|KB"; then
                   # 显示文件大小信息
                   echo "$line" | grep -oE "[0-9]+[.][0-9]+[KM]?B|[0-9]+[KM]?B" | head -1
               fi
           done; then
            echo ""  # 换行
            # 检查文件是否下载成功
            if [ -f "$output_file" ] && [ -s "$output_file" ]; then
                return 0
            fi
        else
            # 如果管道失败，检查下载是否成功
            if [ -f "$output_file" ] && [ -s "$output_file" ]; then
                print_info "下载完成"
                return 0
            fi
        fi
    elif command -v curl >/dev/null 2>&1; then
        # 使用 curl 显示进度条
        print_info "正在下载..."
        # curl 的进度条使用 -# 显示
        if curl -# --connect-timeout 10 --max-time 60 -L \
           -o "$output_file" "$url" 2>&1; then
            echo ""  # 换行
            if [ -f "$output_file" ] && [ -s "$output_file" ]; then
                return 0
            fi
        fi
    fi
    
    return 1
}

# 下载 Xray 二进制文件
download_xray() {
    local version=$1
    local arch=$2
    local output_file=$3
    
    print_info "下载 Xray v${version} (${arch})..."
    
    # 获取所有可用的下载源（包括镜像）
    local urls=($(get_mirror_urls "$version" "$arch"))
    local total_sources=${#urls[@]}
    local tried_sources=0
    
    # 尝试从各个源下载
    for url in "${urls[@]}"; do
        ((tried_sources++))
        
        # 判断是主源还是镜像源
        local source_name=""
        if [[ "$url" == *"github.com"* ]] && [[ "$url" != *"mirror"* ]] && [[ "$url" != *"ghproxy"* ]] && [[ "$url" != *"fastgit"* ]] && [[ "$url" != *"gitclone"* ]]; then
            source_name="GitHub 官方源"
        else
            # 提取镜像源名称
            if [[ "$url" == *"tsinghua"* ]]; then
                source_name="清华镜像"
            elif [[ "$url" == *"ghproxy"* ]]; then
                source_name="GitHub 代理镜像"
            elif [[ "$url" == *"fastgit"* ]]; then
                source_name="FastGit 镜像"
            elif [[ "$url" == *"gitclone"* ]]; then
                source_name="GitClone 镜像"
            else
                source_name="镜像源"
            fi
        fi
        
        print_info "尝试从 $source_name 下载 ($tried_sources/$total_sources)..."
        
        # 快速检测连接（3秒内）
        print_info "检测连接..."
        if ! quick_check_url "$url"; then
            print_warn "$source_name 不可达，立即切换到下一个源..."
            continue  # 立即跳过，不等待超时
        fi
        
        print_info "连接正常，开始下载..."
        print_info "下载地址: $url"
        
        # 尝试下载
        if try_download_from_url "$url" "$output_file"; then
            # 验证文件大小（至少应该大于 1MB）
            local file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo "0")
            if [ "$file_size" -gt 1048576 ]; then
                if [[ "$url" != *"github.com"* ]] || [[ "$url" == *"mirror"* ]] || [[ "$url" == *"ghproxy"* ]] || [[ "$url" == *"fastgit"* ]] || [[ "$url" == *"gitclone"* ]]; then
                    print_success "从镜像源下载成功"
                else
                    print_success "从 GitHub 官方源下载成功"
                fi
                return 0
            else
                print_warn "下载的文件大小异常，尝试下一个源..."
                rm -f "$output_file" 2>/dev/null
            fi
        else
            if [ $tried_sources -lt $total_sources ]; then
                print_warn "下载失败，尝试下一个镜像源..."
            fi
        fi
    done
    
    # 所有源都失败
    print_error "所有下载源均失败"
    echo ""
    print_info "════════════════════════════════════════"
    print_info "解决方案："
    print_info "════════════════════════════════════════"
    print_info ""
    print_info "方案 1: 配置代理（如果服务器有代理）"
    print_info "  export http_proxy=http://proxy:port"
    print_info "  export https_proxy=http://proxy:port"
    print_info "  然后重新运行部署"
    print_info ""
    print_info "方案 2: 从本地传输 Xray 二进制文件"
    print_info "  1. 在本地下载 Xray:"
    print_info "     wget ${urls[0]}"
    print_info "  2. 解压并上传到服务器:"
    print_info "     unzip Xray-linux-${arch}.zip"
    print_info "     scp -P <port> -i <key> xray root@<server>:/tmp/xray"
    print_info "  3. 在服务器上安装:"
    print_info "     chmod +x /tmp/xray"
    print_info "     mv /tmp/xray /usr/local/bin/xray"
    print_info ""
    print_info "方案 3: 检查网络配置"
    print_info "  - 检查防火墙规则"
    print_info "  - 检查 DNS 配置"
    print_info "  - 检查路由表"
    echo ""
    
    return 1
    
    # 检查文件是否下载成功
    if [ ! -f "$output_file" ] || [ ! -s "$output_file" ]; then
        print_error "下载的文件无效"
        return 1
    fi
    
    # 显示文件大小
    local file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo "unknown")
    if [ "$file_size" != "unknown" ]; then
        # 转换为人类可读格式
        if [ "$file_size" -gt 1048576 ]; then
            local size_mb=$(echo "scale=2; $file_size / 1048576" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $file_size / 1048576}")
            print_success "下载完成 (大小: ${size_mb} MB)"
        elif [ "$file_size" -gt 1024 ]; then
            local size_kb=$(echo "scale=2; $file_size / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $file_size / 1024}")
            print_success "下载完成 (大小: ${size_kb} KB)"
        else
            print_success "下载完成 (大小: ${file_size} 字节)"
        fi
    else
        print_success "下载完成"
    fi
    
    return 0
}

# 安装 Xray 二进制文件
install_xray_binary() {
    local binary_file=$1
    local install_path="/usr/local/bin/xray"
    
    # 检查 Xray 服务是否正在运行
    if systemctl is-active --quiet xray 2>/dev/null; then
        print_warn "检测到 Xray 服务正在运行，将先停止服务"
        systemctl stop xray 2>/dev/null || true
        sleep 1
    fi
    
    # 如果文件存在且被占用，等待释放
    if [ -f "$install_path" ]; then
        if command -v lsof >/dev/null 2>&1 && lsof "$install_path" >/dev/null 2>&1; then
            print_warn "Xray 文件正在被使用，等待释放..."
            sleep 2
        fi
    fi
    
    # 如果目标文件存在，先删除（避免 Text file busy 错误）
    if [ -f "$install_path" ]; then
        rm -f "$install_path"
        sleep 0.5
    fi
    
    # 复制文件
    cp "$binary_file" "$install_path" || {
        print_error "复制文件失败"
        return 1
    }
    
    # 设置执行权限
    chmod +x "$install_path" || {
        print_error "设置执行权限失败"
        return 1
    }
    
    # 验证安装
    if [ -f "$install_path" ] && [ -x "$install_path" ]; then
        local xray_version=$("$install_path" version 2>/dev/null | head -n 1 || echo "unknown")
        print_success "Xray 安装成功: $xray_version"
        print_info "安装路径: $install_path"
        return 0
    else
        print_error "Xray 安装验证失败"
        return 1
    fi
}

# 创建日志目录
create_log_directory() {
    local log_dir="/var/log/xray"
    
    print_info "创建日志目录: $log_dir"
    
    mkdir -p "$log_dir" || {
        print_error "创建日志目录失败"
        return 1
    }
    
    # 设置目录权限（nobody 用户）
    if id nobody >/dev/null 2>&1; then
        chown nobody:nogroup "$log_dir" 2>/dev/null || \
        chown nobody:nobody "$log_dir" 2>/dev/null || \
        chown nobody:root "$log_dir" 2>/dev/null || true
        chmod 755 "$log_dir"
        print_success "日志目录已创建，所有者: nobody"
    else
        print_warn "未找到 nobody 用户，使用默认权限"
        chmod 755 "$log_dir"
    fi
    
    return 0
}

# 创建配置目录（仅创建目录，不生成配置）
create_config_directory() {
    local config_dir="/usr/local/etc/xray"
    
    print_info "创建配置目录: $config_dir"
    
    mkdir -p "$config_dir" || {
        print_error "创建配置目录失败"
        return 1
    }
    
    chmod 755 "$config_dir"
    print_success "配置目录已创建"
    return 0
}

# 主函数：安装 Xray
install_xray() {
    local version=${1:-""}
    local expected_hash=${2:-""}
    
    # 检查 root 权限
    if [ "$EUID" -ne 0 ]; then
        print_error "此操作需要 root 权限"
        return 1
    fi
    
    # 先检查 Xray 是否已安装（在开始安装前检查）
    local installed_version=$(get_installed_version)
    if [ -n "$installed_version" ] && [ "$installed_version" != "unknown" ]; then
        print_info "检测到已安装的 Xray 版本: v$installed_version"
        
        # 如果指定了版本，检查是否匹配
        if [ -n "$version" ]; then
            if [ "$installed_version" = "$version" ]; then
                print_success "Xray v$version 已安装，无需重新安装"
                return 0
            else
                print_info "已安装版本 (v$installed_version) 与目标版本 (v$version) 不匹配，将进行更新"
            fi
        else
            # 未指定版本，使用已安装的版本
            print_success "Xray v$installed_version 已安装，无需重新安装"
            return 0
        fi
    fi
    
    # 只有在需要安装时才显示开始安装信息
    print_info "=========================================="
    print_info "开始安装 Xray-core"
    print_info "=========================================="
    
    # 检测架构
    local arch=$(detect_arch)
    if [ $? -ne 0 ]; then
        return 1
    fi
    print_info "检测到系统架构: $(uname -m) (Xray: $arch)"
    
    # 获取版本号
    if [ -z "$version" ]; then
        version=$(get_latest_version)
    fi
    print_info "Xray 版本: v$version"
    
    # 创建临时目录
    local temp_dir=$(mktemp -d)
    if [ ! -d "$temp_dir" ]; then
        print_error "创建临时目录失败"
        return 1
    fi
    
    # 清理函数
    cleanup() {
        rm -rf "$temp_dir" 2>/dev/null
    }
    trap cleanup EXIT
    
    # 下载 Xray
    local zip_file="$temp_dir/xray.zip"
    if ! download_xray "$version" "$arch" "$zip_file"; then
        # 如果下载失败，但 Xray 已存在，检查是否可以使用现有版本
        # 只有在未指定版本或版本匹配时才可以使用已安装的版本
        if [ -n "$installed_version" ] && [ "$installed_version" != "unknown" ]; then
            print_warn "下载失败，但检测到 Xray 已安装 (v$installed_version)"
            # 如果未指定版本，或已安装版本与目标版本匹配，可以使用已安装的版本
            if [ -z "$version" ] || [ "$installed_version" = "$version" ]; then
                print_success "使用已安装的 Xray 版本: v$installed_version"
                print_info "=========================================="
                print_success "Xray-core 安装完成！"
                print_info "=========================================="
                return 0
            else
                print_error "已安装版本 (v$installed_version) 与目标版本 (v$version) 不匹配，且无法下载新版本"
                return 1
            fi
        else
            # 如果 Xray 未安装且下载失败，需要重新检查（可能是在下载过程中安装的）
            local current_installed=$(get_installed_version)
            if [ -n "$current_installed" ] && [ "$current_installed" != "unknown" ]; then
                print_warn "下载失败，但检测到 Xray 已安装 (v$current_installed)"
                if [ -z "$version" ] || [ "$current_installed" = "$version" ]; then
                    print_success "使用已安装的 Xray 版本: v$current_installed"
                    print_info "=========================================="
                    print_success "Xray-core 安装完成！"
                    print_info "=========================================="
                    return 0
                fi
            fi
        fi
        return 1
    fi
    
    # 验证哈希（如果提供）
    if [ -n "$expected_hash" ]; then
        if ! verify_hash "$zip_file" "$expected_hash"; then
            return 1
        fi
    fi
    
    # 解压
    print_info "解压文件..."
    if ! unzip -q "$zip_file" -d "$temp_dir" 2>/dev/null; then
        print_error "解压失败"
        return 1
    fi
    
    # 检查解压后的文件
    local binary_file="$temp_dir/xray"
    if [ ! -f "$binary_file" ] || [ ! -x "$binary_file" ]; then
        print_error "解压后的文件无效"
        return 1
    fi
    
    # 安装二进制文件
    if ! install_xray_binary "$binary_file"; then
        return 1
    fi
    
    # 创建目录结构
    create_config_directory || true
    create_log_directory || true
    
    print_info "=========================================="
    print_success "Xray-core 安装完成！"
    print_info "=========================================="
    
    return 0
}

# 检查 Xray 是否已安装
check_xray_installed() {
    local xray_bin="/usr/local/bin/xray"
    
    if [ -f "$xray_bin" ] && [ -x "$xray_bin" ]; then
        local version=$("$xray_bin" version 2>/dev/null | head -n 1 || echo "unknown")
        echo "$version"
        return 0
    else
        return 1
    fi
}

# 获取已安装的 Xray 版本
get_installed_version() {
    local xray_bin="/usr/local/bin/xray"
    
    if [ -f "$xray_bin" ] && [ -x "$xray_bin" ]; then
        "$xray_bin" version 2>/dev/null | head -n 1 | sed 's/.*v\([0-9.]*\).*/\1/' || echo "unknown"
    else
        echo ""
    fi
}

# 更新 Xray（如果已安装）
update_xray() {
    local current_version=$(get_installed_version)
    local latest_version=$(get_latest_version)
    
    if [ -z "$current_version" ]; then
        print_info "Xray 未安装，执行全新安装"
        install_xray
        return $?
    fi
    
    print_info "当前版本: v$current_version"
    print_info "最新版本: v$latest_version"
    
    if [ "$current_version" = "$latest_version" ]; then
        print_info "已是最新版本，无需更新"
        return 0
    fi
    
    print_info "开始更新 Xray..."
    install_xray "$latest_version"
    return $?
}

# 如果脚本被直接执行（而非被 source），运行安装
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    install_xray
fi
