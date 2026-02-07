#!/bin/bash

# 多机管理模块
# 实现从本地控制端向远程 VPS 的一键式部署流程

# 颜色定义（如果未定义）
if [ -z "${RED}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
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
    print_title() {
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}$1${NC}"
        echo -e "${BLUE}========================================${NC}"
    }
fi

# 全局变量
REMOTE_MODULES_DIR="/tmp/xray_ops"
DEPLOY_RESULTS_FILE=""

# 构建 SSH 命令
build_ssh_cmd() {
    local server_ip=$1
    local ssh_port=$2
    local ssh_user=${3:-root}
    local ssh_key=${4:-""}
    
    local ssh_cmd="ssh -p $ssh_port"
    ssh_cmd="$ssh_cmd -o StrictHostKeyChecking=no"
    ssh_cmd="$ssh_cmd -o ConnectTimeout=10"
    ssh_cmd="$ssh_cmd -o BatchMode=yes"
    ssh_cmd="$ssh_cmd -o UserKnownHostsFile=/dev/null"
    
    # 展开 ~ 路径
    if [ -n "$ssh_key" ]; then
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        if [ -f "$ssh_key" ]; then
            ssh_cmd="$ssh_cmd -i $ssh_key"
        else
            print_warn "SSH 密钥文件不存在: $ssh_key，将尝试密码认证"
        fi
    fi
    
    # 添加默认 SSH 选项（如果设置了环境变量）
    if [ -n "${SSH_OPTS:-}" ]; then
        ssh_cmd="$ssh_cmd $SSH_OPTS"
    else
        # 默认选项
        ssh_cmd="$ssh_cmd -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    fi
    
    ssh_cmd="$ssh_cmd $ssh_user@$server_ip"
    echo "$ssh_cmd"
}

# 构建 SCP 命令
build_scp_cmd() {
    local server_ip=$1
    local ssh_port=$2
    local ssh_user=${3:-root}
    local ssh_key=${4:-""}
    
    local scp_cmd="scp -r -P $ssh_port"
    
    # 使用环境变量中的 SCP 选项，如果没有则使用默认值
    if [ -n "${SCP_OPTS:-}" ]; then
        scp_cmd="$scp_cmd $SCP_OPTS"
    else
        scp_cmd="$scp_cmd -o StrictHostKeyChecking=no"
        scp_cmd="$scp_cmd -o ConnectTimeout=10"
        scp_cmd="$scp_cmd -o BatchMode=yes"
        scp_cmd="$scp_cmd -o UserKnownHostsFile=/dev/null"
    fi
    
    if [ -n "$ssh_key" ]; then
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        if [ -f "$ssh_key" ]; then
            scp_cmd="$scp_cmd -i $ssh_key"
        fi
    fi
    
    echo "$scp_cmd"
}

# SSH 连接预检（检查密钥是否生效）
precheck_ssh_connection() {
    local server_alias=$1
    local server_ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    
    print_info "[$server_alias] 预检 SSH 连接..."
    
    local ssh_cmd=$(build_ssh_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
    
    # 测试连接（超时 5 秒）
    if timeout 5 $ssh_cmd "echo 'SSH connection test successful'" >/dev/null 2>&1; then
        print_success "[$server_alias] SSH 连接预检通过"
        return 0
    else
        print_error "[$server_alias] SSH 连接预检失败"
        print_error "  请检查:"
        print_error "  - 网络连通性: ping $server_ip"
        print_error "  - SSH 端口: $ssh_port"
        print_error "  - SSH 密钥权限: chmod 600 $ssh_key"
        print_error "  - 密钥是否正确"
        return 1
    fi
}

# 分发 modules 文件夹到远程服务器
distribute_modules() {
    local server_alias=$1
    local server_ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local local_modules_dir=$6
    
    print_info "[$server_alias] 分发模块文件到远程服务器..."
    
    if [ ! -d "$local_modules_dir" ]; then
        print_error "[$server_alias] 本地模块目录不存在: $local_modules_dir"
        return 1
    fi
    
    local scp_cmd=$(build_scp_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
    local ssh_cmd=$(build_ssh_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
    
    # 清理远程临时目录（如果存在）
    $ssh_cmd "rm -rf $REMOTE_MODULES_DIR" 2>/dev/null || true
    
    # 创建远程临时目录
    $ssh_cmd "mkdir -p $REMOTE_MODULES_DIR" || {
        print_error "[$server_alias] 创建远程目录失败"
        return 1
    }
    
    # 上传整个 modules 目录
    print_info "[$server_alias] 上传模块文件..."
    if $scp_cmd "$local_modules_dir"/* "$ssh_user@$server_ip:$REMOTE_MODULES_DIR/" 2>/dev/null; then
        print_success "[$server_alias] 模块文件上传完成"
        return 0
    else
        print_error "[$server_alias] 模块文件上传失败"
        return 1
    fi
}

# 远程执行部署流程（单台服务器）
deploy_to_server_remote() {
    local server_alias=$1
    local server_ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local config_file=$6
    
    local ssh_cmd=$(build_ssh_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
    local remote_modules="$REMOTE_MODULES_DIR"
    
    print_info "[$server_alias] 开始远程部署流程..."
    
    # 步骤 1: 执行系统优化
    print_info "[$server_alias] 步骤 1/3: 执行系统优化..."
    echo "----------------------------------------"
    if $ssh_cmd "bash $remote_modules/sys_tuner.sh" 2>&1 | sed "s/^/  [$server_alias] /"; then
        echo "----------------------------------------"
        print_success "[$server_alias] 系统优化完成"
    else
        local step1_exit=${PIPESTATUS[0]}
        echo "----------------------------------------"
        print_warn "[$server_alias] 系统优化部分失败 (退出码: $step1_exit)，继续部署..."
    fi
    
    # 步骤 2: 安装 Xray 二进制文件（关键步骤，失败则停止）
    print_info "[$server_alias] 步骤 2/4: 安装 Xray-core..."
    echo "----------------------------------------"
    if $ssh_cmd "bash $remote_modules/xray_manager.sh" 2>&1 | sed "s/^/  [$server_alias] /"; then
        local step2_exit=0
    else
        local step2_exit=${PIPESTATUS[0]}
    fi
    echo "----------------------------------------"
    
    # 验证 Xray 是否真正安装成功
    if [ $step2_exit -eq 0 ]; then
        # 再次验证 Xray 文件是否存在且可执行
        if $ssh_cmd "test -f /usr/local/bin/xray && test -x /usr/local/bin/xray" 2>/dev/null; then
            local xray_version=$($ssh_cmd "/usr/local/bin/xray version 2>/dev/null | head -1" || echo "unknown")
            print_success "[$server_alias] Xray 安装成功: $xray_version"
        else
            print_error "[$server_alias] Xray 安装失败：二进制文件不存在或不可执行"
            return 1
        fi
    else
        print_error "[$server_alias] Xray 安装失败 (退出码: $step2_exit)"
        print_error "[$server_alias] 部署终止，请先解决 Xray 安装问题"
        return 1
    fi
    
    # 步骤 3: 在服务器上生成配置文件（使用已安装的 Xray）
    print_info "[$server_alias] 步骤 3/4: 生成配置文件..."
    echo "----------------------------------------"
    
    # 检查配置生成模块是否已上传
    if ! $ssh_cmd "test -f $remote_modules/config_generator.sh" >/dev/null 2>&1; then
        print_error "[$server_alias] 配置生成模块未找到"
        return 1
    fi
    
    # 在远程执行配置生成（静默模式，只输出错误）
    if $ssh_cmd "REMOTE_MODULES_DIR='$remote_modules' SERVER_IP='$server_ip' bash -c '
source \"\$REMOTE_MODULES_DIR/config_generator.sh\" >/dev/null 2>&1 || {
    echo \"ERROR: 无法加载配置生成模块\" >&2
    exit 1
}
mkdir -p /usr/local/etc/xray || {
    echo \"ERROR: 无法创建配置目录\" >&2
    exit 1
}
if declare -f generate_vless_reality_grpc_config >/dev/null 2>&1; then
    # 静默生成配置（重定向所有输出）
    generate_vless_reality_grpc_config \"\$SERVER_IP\" 443 \"/usr/local/etc/xray/config.json\" \"\" \"/usr/local/bin/xray\" >/dev/null 2>&1
    if [ \$? -eq 0 ] && [ -f \"/usr/local/etc/xray/config.json\" ] && [ -s \"/usr/local/etc/xray/config.json\" ]; then
        chmod 644 /usr/local/etc/xray/config.json
        exit 0
    else
        echo \"ERROR: 配置文件生成失败或文件为空\" >&2
        exit 1
    fi
else
    echo \"ERROR: 配置生成函数不可用\" >&2
    exit 1
fi
'" 2>&1 | sed "s/^/  [$server_alias] /"; then
        local gen_exit=0
    else
        local gen_exit=${PIPESTATUS[0]}
    fi
    
    if [ $gen_exit -ne 0 ]; then
        print_error "[$server_alias] 配置文件生成失败"
        return 1
    fi
    
    # 验证配置文件
    if $ssh_cmd "test -f /usr/local/etc/xray/config.json" >/dev/null 2>&1; then
        local config_size=$($ssh_cmd "stat -f%z /usr/local/etc/xray/config.json 2>/dev/null || stat -c%s /usr/local/etc/xray/config.json 2>/dev/null || echo '0'")
        print_success "[$server_alias] 配置文件生成成功 (大小: $config_size 字节)"
    else
        print_error "[$server_alias] 配置文件生成但验证失败"
        return 1
    fi
    echo "----------------------------------------"
    
    # 步骤 4: 注册 systemd 服务（关键步骤，失败则停止）
    print_info "[$server_alias] 步骤 4/4: 注册 systemd 服务..."
    echo "----------------------------------------"
    if $ssh_cmd "bash $remote_modules/service_manager.sh" 2>&1 | sed "s/^/  [$server_alias] /"; then
        local exit_code=0
    else
        local exit_code=${PIPESTATUS[0]}
    fi
    echo "----------------------------------------"
    
    if [ $exit_code -ne 0 ]; then
        print_error "[$server_alias] 服务注册失败 (退出码: $exit_code)"
        print_error "[$server_alias] 部署终止"
        return 1
    fi
    
    # 验证服务文件是否存在
    if ! $ssh_cmd "test -f /etc/systemd/system/xray.service" 2>/dev/null; then
        print_error "[$server_alias] 服务文件创建失败"
        return 1
    fi
    
    print_success "[$server_alias] 服务注册完成"
    
    # 启动服务（配置文件已在步骤3生成）
    print_info "[$server_alias] 启动 Xray 服务..."
    $ssh_cmd "systemctl reset-failed xray" >/dev/null 2>&1 || true
    
    if $ssh_cmd "bash -c 'source $remote_modules/service_manager.sh && start_xray_service'" 2>&1 | sed "s/^/  [$server_alias] /"; then
        local start_exit=0
    else
        local start_exit=${PIPESTATUS[0]}
    fi
    
    # 等待并验证服务状态
    sleep 2
    $ssh_cmd "systemctl reset-failed xray" >/dev/null 2>&1 || true
    sleep 1
    
    if $ssh_cmd "systemctl is-active --quiet xray" >/dev/null 2>&1; then
        print_success "[$server_alias] 服务启动成功"
    else
        print_warn "[$server_alias] 服务启动失败 (退出码: $start_exit)"
        print_info "[$server_alias] 查看日志: journalctl -u xray -n 50"
    fi
    
    # 步骤 6: 清理远程临时文件
    print_info "[$server_alias] 清理临时文件..."
    $ssh_cmd "rm -rf $REMOTE_MODULES_DIR" >/dev/null 2>&1 || true
    
    return 0
}

# 单台服务器完整部署流程（串行执行）
deploy_single_server() {
    local server_alias=$1
    local server_ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local config_file=$6
    local local_modules_dir=$7
    
    local start_time=$(date +%s)
    local result="FAILED"
    
    print_title "部署到: $server_alias ($server_ip:$ssh_port)"
    
    # 0. 网络预检（ping 检查）
    if command -v ping >/dev/null 2>&1; then
        if ! ping -c 1 -W 2 "$server_ip" >/dev/null 2>&1 && ! ping -c 1 -w 2000 "$server_ip" >/dev/null 2>&1; then
            print_error "服务器 $server_ip 网络不可达（ping 失败），跳过部署"
            if [ -n "${DEPLOY_RESULTS_FILE:-}" ] && [ -f "${DEPLOY_RESULTS_FILE:-}" ]; then
                echo "$server_alias|FAILED|网络不可达(ping失败)|$(( $(date +%s) - start_time ))秒" >> "$DEPLOY_RESULTS_FILE"
            fi
            return 1
        fi
    fi
    
    # 1. SSH 连接预检
    if ! precheck_ssh_connection "$server_alias" "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key"; then
        if [ -n "${DEPLOY_RESULTS_FILE:-}" ] && [ -f "${DEPLOY_RESULTS_FILE:-}" ]; then
            echo "$server_alias|FAILED|SSH连接失败|$(( $(date +%s) - start_time ))秒" >> "$DEPLOY_RESULTS_FILE"
        fi
        return 1
    fi
    
    # 2. 分发模块文件
    if ! distribute_modules "$server_alias" "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key" "$local_modules_dir"; then
        if [ -n "${DEPLOY_RESULTS_FILE:-}" ] && [ -f "${DEPLOY_RESULTS_FILE:-}" ]; then
            echo "$server_alias|FAILED|模块分发失败|$(( $(date +%s) - start_time ))秒" >> "$DEPLOY_RESULTS_FILE"
        fi
        return 1
    fi
    
    # 3. 远程执行部署
    if deploy_to_server_remote "$server_alias" "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key" "$config_file"; then
        result="SUCCESS"
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_success "[$server_alias] 部署完成（耗时: ${duration}秒）"
    else
        print_error "[$server_alias] 部署失败"
    fi
    
    # 记录结果（确保文件存在）
    if [ -n "${DEPLOY_RESULTS_FILE:-}" ] && [ -f "${DEPLOY_RESULTS_FILE:-}" ]; then
        echo "$server_alias|$result|部署完成|$(( $(date +%s) - start_time ))秒" >> "$DEPLOY_RESULTS_FILE"
    fi
    return 0
}

# 解析服务器配置（使用 yq 或简单解析）
parse_server_config() {
    local yaml_file=$1
    local server_alias=${2:-""}
    
    if [ ! -f "$yaml_file" ]; then
        print_error "配置文件不存在: $yaml_file"
        return 1
    fi
    
    # 如果安装了 yq，使用 yq 解析
    if command -v yq >/dev/null 2>&1; then
        if [ -n "$server_alias" ]; then
            # 使用 jq 处理多行 description（如果可用）
            if command -v jq >/dev/null 2>&1; then
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json 2>/dev/null | \
                    jq -c 'if .description then .description = (.description | gsub("\n"; " ")) else . end' 2>/dev/null || \
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json 2>/dev/null
            else
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json -c 2>/dev/null || \
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json 2>/dev/null
            fi
        else
            # 使用 jq 处理多行 description（如果可用）
            if command -v jq >/dev/null 2>&1; then
                yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null | \
                    jq -c 'if .description then .description = (.description | gsub("\n"; " ")) else . end' 2>/dev/null || \
                yq eval '.servers[]' "$yaml_file" -o json -c 2>/dev/null || \
                yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null
            else
                yq eval '.servers[]' "$yaml_file" -o json -c 2>/dev/null || \
                yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null
            fi
        fi
    else
        print_error "需要安装 yq 工具来解析 YAML 配置"
        print_info "安装方法: https://github.com/mikefarah/yq"
        return 1
    fi
}

# 提取服务器字段
extract_server_field() {
    local server_json=$1
    local field=$2
    
    # 优先使用 jq 解析（更可靠）
    if command -v jq >/dev/null 2>&1; then
        local value=$(echo "$server_json" | jq -r ".$field // empty" 2>/dev/null)
        if [ -n "$value" ] && [ "$value" != "null" ]; then
            # 如果是路径字段（ssh_key），自动展开 ~
            if [ "$field" = "ssh_key" ] && [[ "$value" == ~* ]]; then
                echo "$value" | sed "s|^~|$HOME|"
            else
                echo "$value"
            fi
            return 0
        fi
    fi
    
    # 备选方案：使用 grep 和 cut
    local value=$(echo "$server_json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | \
        sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1)
    
    if [ -n "$value" ]; then
        # 如果是路径字段（ssh_key），自动展开 ~
        if [ "$field" = "ssh_key" ] && [[ "$value" == ~* ]]; then
            echo "$value" | sed "s|^~|$HOME|"
        else
            echo "$value"
        fi
        return 0
    fi
    
    # 尝试匹配数字值
    value=$(echo "$server_json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*[0-9]*" | \
        sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p" | head -1)
    
    if [ -n "$value" ]; then
        echo "$value"
        return 0
    fi
    
    # 返回空
    return 1
}

# 批量部署（支持串行/并行）
batch_deploy() {
    local yaml_file=$1
    local script_dir=$2
    local selected_alias=${3:-""}
    local parallel_mode=${4:-false}
    local max_parallel=${5:-5}
    
    print_title "批量部署 Xray-core"
    
    if [ ! -f "$yaml_file" ]; then
        print_error "配置文件不存在: $yaml_file"
        return 1
    fi
    
    # 解析服务器列表
    local servers
    if [ -n "$selected_alias" ]; then
        servers=$(parse_server_config "$yaml_file" "$selected_alias")
    else
        servers=$(parse_server_config "$yaml_file")
    fi
    
    if [ -z "$servers" ]; then
        print_error "未找到服务器配置"
        return 1
    fi
    
    # 统计服务器数量
    local server_count=$(echo "$servers" | grep -c '"alias"' || echo "0")
    print_info "找到 $server_count 台服务器"
    
    # 确认部署模式
    if [ "$parallel_mode" = "true" ]; then
        print_info "部署模式: 并行（最大并发数: $max_parallel）"
    else
        print_info "部署模式: 串行"
    fi
    
    echo ""
    echo -ne "${YELLOW}确认开始部署？[y/N]: ${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "已取消部署"
        return 0
    fi
    
    # 准备本地模块目录
    local local_modules_dir="$script_dir/modules"
    if [ ! -d "$local_modules_dir" ]; then
        print_error "模块目录不存在: $local_modules_dir"
        return 1
    fi
    
    # 准备配置文件列表（现在主要在服务器上生成，本地生成作为备用）
    local temp_dir=$(mktemp -d)
    local config_files=()
    
    print_info "准备配置文件..."
    print_info "注意: 配置文件将在服务器上自动生成（使用已安装的 Xray）"
    print_info "本地生成仅作为备用方案"
    echo ""
    
    # 为每台服务器准备配置记录（即使不生成，也记录以便后续处理）
    echo "$servers" | while IFS= read -r server_json; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        
        local alias=$(extract_server_field "$server_json" "alias")
        local ip=$(extract_server_field "$server_json" "ip")
        
        if [ -z "$alias" ] || [ -z "$ip" ]; then
            continue
        fi
        
        # 记录空路径，表示将在服务器上生成
        config_files+=("|$alias")
    done
    
    # 创建结果文件
    DEPLOY_RESULTS_FILE=$(mktemp)
    
    # 执行部署
    local deploy_pids=()
    local deploy_count=0
    local server_list=()
    
    # 先收集所有服务器信息
    while IFS= read -r server_json; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        server_list+=("$server_json")
    done <<< "$servers"
    
    # 处理每台服务器
    for server_json in "${server_list[@]}"; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        
        local alias=$(extract_server_field "$server_json" "alias")
        local ip=$(extract_server_field "$server_json" "ip")
        local ssh_port=$(extract_server_field "$server_json" "ssh_port")
        local ssh_user=$(extract_server_field "$server_json" "ssh_user")
        local ssh_key=$(extract_server_field "$server_json" "ssh_key")
        
        ssh_port=${ssh_port:-22}
        ssh_user=${ssh_user:-root}
        
        if [ -z "$alias" ] || [ -z "$ip" ]; then
            continue
        fi
        
        # 查找对应的配置文件
        local config_file=""
        for config_entry in "${config_files[@]}"; do
            if echo "$config_entry" | grep -q "|$alias$"; then
                config_file=$(echo "$config_entry" | cut -d'|' -f1)
                # 检查配置文件是否有效（不为空且文件存在）
                if [ -n "$config_file" ] && [ -f "$config_file" ] && [ -s "$config_file" ]; then
                    print_info "[$alias] 找到配置文件: $config_file"
                    break
                else
                    print_warn "[$alias] 配置文件未生成或无效，将跳过步骤 4"
                    config_file=""  # 清空，确保后续步骤知道没有配置文件
                    break
                fi
            fi
        done
        
        # 执行部署
        if [ "$parallel_mode" = "true" ]; then
            # 并行模式：后台执行
            (
                deploy_single_server "$alias" "$ip" "$ssh_port" "$ssh_user" "$ssh_key" \
                    "$config_file" "$local_modules_dir"
            ) &
            deploy_pids+=($!)
            ((deploy_count++))
            
            # 控制并发数
            while [ $deploy_count -ge $max_parallel ]; do
                wait "${deploy_pids[0]}"
                deploy_pids=("${deploy_pids[@]:1}")
                ((deploy_count--))
            done
        else
            # 串行模式：顺序执行
            deploy_single_server "$alias" "$ip" "$ssh_port" "$ssh_user" "$ssh_key" \
                "$config_file" "$local_modules_dir"
            echo "" # 空行分隔
        fi
    done
    
    # 等待所有并行任务完成
    if [ "$parallel_mode" = "true" ] && [ ${#deploy_pids[@]} -gt 0 ]; then
        print_info "等待所有部署任务完成..."
        for pid in "${deploy_pids[@]}"; do
            wait "$pid"
        done
    fi
    
    # 清理临时文件
    rm -rf "$temp_dir"
    
    # 显示部署结果汇总
    print_title "部署结果汇总"
    
    local success_count=0
    local fail_count=0
    
    if [ -f "$DEPLOY_RESULTS_FILE" ] && [ -s "$DEPLOY_RESULTS_FILE" ]; then
        while IFS='|' read -r alias status reason duration; do
            [ -z "$alias" ] && continue
            if [ "$status" = "SUCCESS" ]; then
                echo -e "${GREEN}✓${NC} $alias - ${GREEN}SUCCESS${NC} - $reason (${duration})"
                ((success_count++))
            else
                echo -e "${RED}✗${NC} $alias - ${RED}FAILED${NC} - $reason (${duration})"
                ((fail_count++))
            fi
        done < "$DEPLOY_RESULTS_FILE"
        
        # 清理结果文件
        rm -f "$DEPLOY_RESULTS_FILE"
    else
        print_warn "没有部署结果记录"
        print_info "可能的原因："
        echo "  1. 所有服务器在部署前被跳过（网络不可达、SSH连接失败等）"
        echo "  2. 配置文件解析失败"
        echo "  3. 没有可用的服务器配置"
        echo ""
        print_info "建议："
        echo "  - 检查服务器网络连通性: ./main.sh status"
        echo "  - 检查 SSH 连接: ./main.sh health"
        echo "  - 查看详细日志（设置 LOG_LEVEL=debug）"
    fi
    
    echo ""
    print_title "统计"
    print_success "成功: $success_count 台"
    if [ $fail_count -gt 0 ]; then
        print_error "失败: $fail_count 台"
    fi
    
    return 0
}

# 批量检查服务器状态
batch_check_status() {
    local yaml_file=$1
    
    print_title "检查所有服务器状态"
    
    if [ ! -f "$yaml_file" ]; then
        print_error "配置文件不存在: $yaml_file"
        return 1
    fi
    
    if ! command -v yq >/dev/null 2>&1; then
        print_error "需要安装 yq 工具来解析 YAML 配置"
        return 1
    fi
    
    local servers=$(parse_server_config "$yaml_file")
    local online_count=0
    local offline_count=0
    
    echo "$servers" | while IFS= read -r server_json; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        
        local alias=$(extract_server_field "$server_json" "alias")
        local ip=$(extract_server_field "$server_json" "ip")
        local ssh_port=$(extract_server_field "$server_json" "ssh_port")
        local ssh_user=$(extract_server_field "$server_json" "ssh_user")
        local ssh_key=$(extract_server_field "$server_json" "ssh_key")
        
        ssh_port=${ssh_port:-22}
        ssh_user=${ssh_user:-root}
        
        if [ -z "$alias" ] || [ -z "$ip" ]; then
            continue
        fi
        
        local ssh_cmd=$(build_ssh_cmd "$ip" "$ssh_port" "$ssh_user" "$ssh_key")
        
        # 检查 SSH 连接
        if ! timeout 5 $ssh_cmd "echo 'test'" >/dev/null 2>&1; then
            print_error "[$alias] SSH 连接失败"
            ((offline_count++))
            continue
        fi
        
        # 检查 Xray 服务状态
        if $ssh_cmd "systemctl is-active --quiet xray" 2>/dev/null; then
            local version=$($ssh_cmd "/usr/local/bin/xray version 2>/dev/null | head -1" || echo "unknown")
            print_success "[$alias] Xray 服务运行中 - $version"
            ((online_count++))
        else
            print_warn "[$alias] Xray 服务未运行"
            ((offline_count++))
        fi
    done
    
    echo ""
    print_title "状态统计"
    print_success "在线: $online_count 台"
    if [ $offline_count -gt 0 ]; then
        print_warn "离线: $offline_count 台"
    fi
}

# 远程卸载单台服务器
uninstall_single_server() {
    local server_alias=$1
    local server_ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local local_modules_dir=$6
    
    local start_time=$(date +%s)
    local result="FAILED"
    
    print_title "卸载: $server_alias ($server_ip:$ssh_port)"
    
    # 0. 网络预检（ping 检查）
    if command -v ping >/dev/null 2>&1; then
        if ! ping -c 1 -W 2 "$server_ip" >/dev/null 2>&1 && ! ping -c 1 -w 2000 "$server_ip" >/dev/null 2>&1; then
            print_error "服务器 $server_ip 网络不可达（ping 失败），跳过卸载"
            return 1
        fi
    fi
    
    # 1. SSH 连接预检
    if ! precheck_ssh_connection "$server_alias" "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key"; then
        return 1
    fi
    
    # 2. 分发模块文件
    if ! distribute_modules "$server_alias" "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key" "$local_modules_dir"; then
        return 1
    fi
    
    # 3. 远程执行卸载
    local ssh_cmd=$(build_ssh_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
    local remote_modules="$REMOTE_MODULES_DIR"
    
    print_info "[$server_alias] 开始远程卸载流程..."
    echo "----------------------------------------"
    if $ssh_cmd "bash $remote_modules/uninstaller.sh" 2>&1 | sed "s/^/  [$server_alias] /"; then
        local uninstall_exit=0
    else
        local uninstall_exit=${PIPESTATUS[0]}
    fi
    echo "----------------------------------------"
    
    if [ $uninstall_exit -eq 0 ]; then
        result="SUCCESS"
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_success "[$server_alias] 卸载完成（耗时: ${duration}秒）"
    else
        print_error "[$server_alias] 卸载失败 (退出码: $uninstall_exit)"
    fi
    
    # 4. 清理远程临时文件
    print_info "[$server_alias] 清理临时文件..."
    $ssh_cmd "rm -rf $REMOTE_MODULES_DIR" >/dev/null 2>&1 || true
    
    return 0
}

# 批量卸载（支持串行/并行）
batch_uninstall() {
    local yaml_file=$1
    local script_dir=$2
    local selected_alias=${3:-""}
    local parallel_mode=${4:-false}
    local max_parallel=${5:-5}
    
    print_title "批量卸载 Xray-core"
    
    if [ ! -f "$yaml_file" ]; then
        print_error "配置文件不存在: $yaml_file"
        return 1
    fi
    
    # 解析服务器列表
    local servers
    if [ -n "$selected_alias" ]; then
        servers=$(parse_server_config "$yaml_file" "$selected_alias")
    else
        servers=$(parse_server_config "$yaml_file")
    fi
    
    if [ -z "$servers" ]; then
        print_error "未找到服务器配置"
        return 1
    fi
    
    # 统计服务器数量
    local server_count=$(echo "$servers" | grep -c '"alias"' || echo "0")
    print_info "找到 $server_count 台服务器"
    
    # 确认卸载模式
    if [ "$parallel_mode" = "true" ]; then
        print_info "卸载模式: 并行（最大并发数: $max_parallel）"
    else
        print_info "卸载模式: 串行"
    fi
    
    echo ""
    echo -e "${RED}警告: 此操作将卸载所有服务器上的 Xray 并清理相关配置${NC}"
    echo ""
    echo -ne "${YELLOW}确认开始卸载？[y/N]: ${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "已取消卸载"
        return 0
    fi
    
    # 准备本地模块目录
    local local_modules_dir="$script_dir/modules"
    if [ ! -d "$local_modules_dir" ]; then
        print_error "模块目录不存在: $local_modules_dir"
        return 1
    fi
    
    # 执行卸载
    local uninstall_pids=()
    local uninstall_count=0
    local server_list=()
    
    # 先收集所有服务器信息
    while IFS= read -r server_json; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        server_list+=("$server_json")
    done <<< "$servers"
    
    # 处理每台服务器
    for server_json in "${server_list[@]}"; do
        [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
        
        local alias=$(extract_server_field "$server_json" "alias")
        local ip=$(extract_server_field "$server_json" "ip")
        local ssh_port=$(extract_server_field "$server_json" "ssh_port")
        local ssh_user=$(extract_server_field "$server_json" "ssh_user")
        local ssh_key=$(extract_server_field "$server_json" "ssh_key")
        
        ssh_port=${ssh_port:-22}
        ssh_user=${ssh_user:-root}
        
        if [ -z "$alias" ] || [ -z "$ip" ]; then
            continue
        fi
        
        # 执行卸载
        if [ "$parallel_mode" = "true" ]; then
            # 并行模式：后台执行
            (
                uninstall_single_server "$alias" "$ip" "$ssh_port" "$ssh_user" "$ssh_key" \
                    "$local_modules_dir"
            ) &
            uninstall_pids+=($!)
            ((uninstall_count++))
            
            # 控制并发数
            while [ $uninstall_count -ge $max_parallel ]; do
                wait "${uninstall_pids[0]}"
                uninstall_pids=("${uninstall_pids[@]:1}")
                ((uninstall_count--))
            done
        else
            # 串行模式：顺序执行
            uninstall_single_server "$alias" "$ip" "$ssh_port" "$ssh_user" "$ssh_key" \
                "$local_modules_dir"
            echo "" # 空行分隔
        fi
    done
    
    # 等待所有并行任务完成
    if [ "$parallel_mode" = "true" ] && [ ${#uninstall_pids[@]} -gt 0 ]; then
        print_info "等待所有卸载任务完成..."
        for pid in "${uninstall_pids[@]}"; do
            wait "$pid"
        done
    fi
    
    print_title "卸载完成"
    return 0
}
