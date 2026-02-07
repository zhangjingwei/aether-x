#!/bin/bash

# 健康检查模块
# 针对多节点环境的健康监测工具，支持TCP/ICMP/应用层检测和IP封锁检测

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
HEALTH_CHECK_TIMEOUT=5
PING_COUNT=4
PING_TIMEOUT=3
DEFAULT_XRAY_PORT=443
LOG_DIR="logs"
LAST_CHECK_LOG="$LOG_DIR/last_check.log"
TEMP_DIR=$(mktemp -d)
CHECK_RESULTS=()

# 确保日志目录存在
mkdir -p "$LOG_DIR"

# 从 multi_server.sh 复用函数（如果未定义）
if ! declare -f build_ssh_cmd >/dev/null; then
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
        
        if [ -n "$ssh_key" ]; then
            ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
            if [ -f "$ssh_key" ]; then
                ssh_cmd="$ssh_cmd -i $ssh_key"
            fi
        fi
        
        ssh_cmd="$ssh_cmd $ssh_user@$server_ip"
        echo "$ssh_cmd"
    }
fi

if ! declare -f parse_server_config >/dev/null; then
    parse_server_config() {
        local yaml_file=$1
        local server_alias=${2:-""}
        
        if [ ! -f "$yaml_file" ]; then
            print_error "配置文件不存在: $yaml_file"
            return 1
        fi
        
        if command -v yq >/dev/null 2>&1; then
            if [ -n "$server_alias" ]; then
                # 使用 -r 选项输出原始值，处理多行字段
                yq eval ".servers[] | select(.alias == \"$server_alias\") | 
                    .description = (.description // \"\" | @json) |
                    ." "$yaml_file" -o json -c 2>/dev/null || \
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json 2>/dev/null | \
                    jq -c 'if .description then .description = (.description | gsub("\n"; " ")) else . end' 2>/dev/null || \
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json 2>/dev/null
            else
                # 使用 -c 选项压缩 JSON 为单行，处理多行 description
                if command -v jq >/dev/null 2>&1; then
                    # 使用 jq 处理多行 description
                    yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null | \
                        jq -c 'if .description then .description = (.description | gsub("\n"; " ")) else . end' 2>/dev/null || \
                    yq eval '.servers[]' "$yaml_file" -o json -c 2>/dev/null || \
                    yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null
                else
                    # 没有 jq，使用 yq 的 -c 选项
                    yq eval '.servers[]' "$yaml_file" -o json -c 2>/dev/null || \
                    yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null
                fi
            fi
        else
            print_error "需要安装 yq 工具来解析 YAML 配置"
            return 1
        fi
    }
fi

if ! declare -f extract_server_field >/dev/null; then
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
fi

# 获取远程服务器的Xray端口
get_remote_xray_port() {
    local ssh_cmd=$1
    local default_port=${2:-$DEFAULT_XRAY_PORT}
    
    # 尝试从配置文件读取端口
    local config_path="/usr/local/etc/xray/config.json"
    local port=$($ssh_cmd "cat $config_path 2>/dev/null | grep -o '\"port\":[0-9]*' | head -1 | cut -d':' -f2" 2>/dev/null)
    
    if [ -n "$port" ] && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
        echo "$port"
    else
        # 尝试从systemd服务文件读取
        port=$($ssh_cmd "systemctl cat xray 2>/dev/null | grep -o '--port=[0-9]*' | head -1 | cut -d'=' -f2" 2>/dev/null)
        if [ -n "$port" ] && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
            echo "$port"
        else
            echo "$default_port"
        fi
    fi
}

# TCP层检测：检查端口连通性
check_tcp_port() {
    local ip=$1
    local port=$2
    local timeout=${3:-$HEALTH_CHECK_TIMEOUT}
    
    # 使用timeout和nc/telnet/bash内置的TCP连接
    if command -v nc >/dev/null 2>&1; then
        if timeout "$timeout" nc -z -w "$timeout" "$ip" "$port" >/dev/null 2>&1; then
            return 0
        fi
    elif command -v telnet >/dev/null 2>&1; then
        if timeout "$timeout" bash -c "echo > /dev/tcp/$ip/$port" >/dev/null 2>&1; then
            return 0
        fi
    else
        # 使用bash内置TCP连接
        if timeout "$timeout" bash -c "echo > /dev/tcp/$ip/$port" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    return 1
}

# ICMP层检测：Ping延迟和丢包率
check_icmp() {
    local ip=$1
    local count=${2:-$PING_COUNT}
    local timeout=${3:-$PING_TIMEOUT}
    
    local ping_result=""
    local avg_latency=""
    local packet_loss=""
    
    if command -v ping >/dev/null 2>&1; then
        # Linux ping
        if ping -c "$count" -W "$timeout" "$ip" >/dev/null 2>&1; then
            ping_result=$(ping -c "$count" -W "$timeout" "$ip" 2>/dev/null)
            avg_latency=$(echo "$ping_result" | grep -oP 'min/avg/max/[^=]*=\s*\K[0-9.]+' | cut -d'/' -f2 2>/dev/null)
            packet_loss=$(echo "$ping_result" | grep -oP '[0-9]+% packet loss' | grep -oP '[0-9]+' | head -1)
            
            if [ -z "$avg_latency" ]; then
                # 尝试另一种格式
                avg_latency=$(echo "$ping_result" | grep -oP 'rtt min/avg/max = [^/]+/([^/]+)/' | cut -d'/' -f2)
            fi
            
            if [ -z "$packet_loss" ]; then
                packet_loss=0
            fi
            
            echo "${avg_latency:-0}|${packet_loss:-0}"
            return 0
        fi
    fi
    
    echo "0|100"
    return 1
}

# 应用层检测：尝试简单的TLS握手（可选）
check_application_layer() {
    local ip=$1
    local port=$2
    local timeout=${3:-$HEALTH_CHECK_TIMEOUT}
    
    # 使用openssl进行TLS握手测试
    if command -v openssl >/dev/null 2>&1; then
        if timeout "$timeout" openssl s_client -connect "$ip:$port" -servername "$ip" </dev/null >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # 如果openssl不可用，返回TCP检查结果
    return 1
}

# IP封锁检测（GFW Check）
check_ip_blocked() {
    local ip=$1
    
    # 方法1: 使用check-host.net API（免费，无需API key）
    if command -v curl >/dev/null 2>&1; then
        # 使用check-host.net的API
        local api_url="https://check-host.net/check-tcp?host=${ip}:443&max_nodes=5"
        local response=$(curl -s -m 10 "$api_url" 2>/dev/null)
        
        if [ -n "$response" ] && echo "$response" | grep -q "request_id"; then
            # 获取request_id
            local request_id=$(echo "$response" | grep -o '"request_id":"[^"]*"' | cut -d'"' -f4 | head -1)
            
            if [ -n "$request_id" ]; then
                # 等待一下让检查完成
                sleep 2
                
                # 获取结果
                local result_url="https://check-host.net/check-result/${request_id}"
                local result=$(curl -s -m 10 "$result_url" 2>/dev/null)
                
                if [ -n "$result" ]; then
                    # 解析结果，统计成功和失败的节点
                    local success_count=0
                    local total_count=0
                    
                    # 解析JSON结果（简单解析）
                    echo "$result" | grep -o '"[^"]*":\[[^]]*\]' | while IFS= read -r node_result; do
                        ((total_count++))
                        if echo "$node_result" | grep -q '"Ok"\|"OK"'; then
                            ((success_count++))
                        fi
                    done
                    
                    # 如果解析成功
                    if [ "$total_count" -gt 0 ]; then
                        local success_rate=$((success_count * 100 / total_count))
                        
                        if [ "$success_rate" -lt 50 ]; then
                            echo "BLOCKED|$success_rate"
                            return 1
                        elif [ "$success_rate" -lt 80 ]; then
                            echo "PARTIAL|$success_rate"
                            return 0
                        else
                            echo "OK|$success_rate"
                            return 0
                        fi
                    fi
                fi
            fi
        fi
    fi
    
    # 方法2: 简单的延迟判断（如果check-host.net不可用）
    # 使用ICMP延迟来判断是否可能被封锁
    local local_ping=$(check_icmp "$ip" 2 2)
    local local_latency=$(echo "$local_ping" | cut -d'|' -f1)
    local local_loss=$(echo "$local_ping" | cut -d'|' -f2)
    
    if [ -z "$local_latency" ] || [ "$local_latency" = "0" ] || [ "$local_loss" = "100" ]; then
        echo "UNKNOWN|0"
        return 2
    fi
    
    # 如果本地延迟异常高（>500ms）或丢包率高（>50%），可能是被封锁
    # 使用awk进行浮点数比较（不依赖bc）
    if echo "$local_latency" | awk '{exit !($1 > 500)}' 2>/dev/null || [ "$local_loss" -gt 50 ]; then
        echo "SUSPECTED|${local_latency}ms/${local_loss}%"
        return 1
    else
        echo "OK|${local_latency}ms"
        return 0
    fi
}

# 检查单个服务器的健康状态
check_single_server() {
    local alias=$1
    local ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local cloud_provider=$6
    
    local result_file="$TEMP_DIR/${alias}.result"
    local start_time=$(date +%s)
    
    # 初始化结果
    local tcp_status="FAIL"
    local tcp_port=$DEFAULT_XRAY_PORT
    local icmp_latency="0"
    local icmp_loss="100"
    local app_status="N/A"
    local ip_status="UNKNOWN"
    local ip_status_detail=""
    local overall_status="FAIL"
    
    # 检查并修复 SSH 密钥权限（WSL 环境特殊处理）
    if [ -n "$ssh_key" ] && [ -f "$ssh_key" ]; then
        local current_perms=$(stat -c "%a" "$ssh_key" 2>/dev/null || stat -f "%OLp" "$ssh_key" 2>/dev/null || echo "")
        if [ -n "$current_perms" ] && [ "$current_perms" != "600" ]; then
            if ! chmod 600 "$ssh_key" 2>/dev/null; then
                # 在 Windows 挂载目录下可能失败，这是正常的，静默处理
                :
            fi
        fi
    fi
    
    # 构建SSH命令
    local ssh_cmd=$(build_ssh_cmd "$ip" "$ssh_port" "$ssh_user" "$ssh_key")
    
    # 尝试获取实际端口（如果SSH可用）
    if timeout 5 $ssh_cmd "echo test" >/dev/null 2>&1; then
        tcp_port=$(get_remote_xray_port "$ssh_cmd" "$DEFAULT_XRAY_PORT")
    fi
    
    # TCP层检测
    if check_tcp_port "$ip" "$tcp_port" "$HEALTH_CHECK_TIMEOUT"; then
        tcp_status="OK"
    fi
    
    # ICMP层检测
    local icmp_result=$(check_icmp "$ip" "$PING_COUNT" "$PING_TIMEOUT")
    icmp_latency=$(echo "$icmp_result" | cut -d'|' -f1)
    icmp_loss=$(echo "$icmp_result" | cut -d'|' -f2)
    
    # 应用层检测（仅在TCP成功时进行）
    if [ "$tcp_status" = "OK" ]; then
        if check_application_layer "$ip" "$tcp_port" "$HEALTH_CHECK_TIMEOUT"; then
            app_status="OK"
        else
            app_status="FAIL"
        fi
    else
        app_status="SKIP"
    fi
    
    # IP封锁检测
    local block_result=$(check_ip_blocked "$ip")
    ip_status=$(echo "$block_result" | cut -d'|' -f1)
    ip_status_detail=$(echo "$block_result" | cut -d'|' -f2)
    
    # 判断整体状态
    if [ "$tcp_status" = "OK" ] && [ "$icmp_loss" -lt 50 ]; then
        if [ "$ip_status" = "OK" ] || [ "$ip_status" = "PARTIAL" ]; then
            overall_status="OK"
        elif [ "$ip_status" = "SUSPECTED" ]; then
            overall_status="WARN"
        else
            overall_status="WARN"
        fi
    elif [ "$tcp_status" = "OK" ]; then
        overall_status="WARN"
    else
        overall_status="FAIL"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # 保存结果到文件
    cat > "$result_file" << EOF
alias=$alias
ip=$ip
cloud_provider=$cloud_provider
tcp_status=$tcp_status
tcp_port=$tcp_port
icmp_latency=$icmp_latency
icmp_loss=$icmp_loss
app_status=$app_status
ip_status=$ip_status
ip_status_detail=$ip_status_detail
overall_status=$overall_status
duration=$duration
EOF
    
    echo "$result_file"
}

# 格式化延迟显示
format_latency() {
    local latency=$1
    if [ -z "$latency" ] || [ "$latency" = "0" ]; then
        echo "N/A"
    else
        # 保留一位小数
        printf "%.1f ms" "$latency" 2>/dev/null || echo "${latency} ms"
    fi
}

# 格式化状态显示（带颜色）
format_status() {
    local status=$1
    case "$status" in
        OK)
            echo -e "${GREEN}OK${NC}"
            ;;
        WARN)
            echo -e "${YELLOW}WARN${NC}"
            ;;
        FAIL)
            echo -e "${RED}FAIL${NC}"
            ;;
        *)
            echo "$status"
            ;;
    esac
}

# 格式化IP状态显示
format_ip_status() {
    local status=$1
    local detail=$2
    
    case "$status" in
        OK)
            echo -e "${GREEN}正常${NC}"
            ;;
        PARTIAL)
            echo -e "${YELLOW}部分封锁(${detail}%)${NC}"
            ;;
        BLOCKED)
            echo -e "${RED}已封锁(${detail}%)${NC}"
            ;;
        SUSPECTED)
            echo -e "${YELLOW}疑似封锁${NC}"
            ;;
        *)
            echo -e "${CYAN}未知${NC}"
            ;;
    esac
}

# 生成健康检查报告表格
generate_health_report() {
    local result_files=("$@")
    
    print_title "健康检查报告"
    
    # 表头
    printf "%-20s %-15s %-8s %-12s %-10s %-20s\n" \
        "节点别名" "云厂商" "状态" "延迟" "丢包率" "IP状态"
    echo "--------------------------------------------------------------------------------"
    
    local ok_count=0
    local warn_count=0
    local fail_count=0
    
    # 读取所有结果并排序
    local sorted_results=($(printf '%s\n' "${result_files[@]}" | sort))
    
    for result_file in "${sorted_results[@]}"; do
        if [ ! -f "$result_file" ] || [ ! -s "$result_file" ]; then
            continue
        fi
        
        # 读取结果（每次循环都重新读取，避免变量被覆盖）
        # 直接使用 source，但立即保存到局部变量
        local file_alias=""
        local file_cloud_provider=""
        local file_overall_status=""
        local file_icmp_latency=""
        local file_icmp_loss=""
        local file_ip_status=""
        local file_ip_status_detail=""
        
        # 在主 shell 中 source，立即保存变量
        if ! source "$result_file" 2>/dev/null; then
            continue
        fi
        
        # 立即保存到局部变量（避免被后续循环覆盖）
        file_alias="$alias"
        file_cloud_provider="$cloud_provider"
        file_overall_status="$overall_status"
        file_icmp_latency="$icmp_latency"
        file_icmp_loss="$icmp_loss"
        file_ip_status="$ip_status"
        file_ip_status_detail="$ip_status_detail"
        
        # 清空全局变量，避免影响下次循环
        # 使用 set +e 临时禁用错误退出，防止 unset 失败导致脚本退出
        set +e
        unset alias cloud_provider overall_status icmp_latency icmp_loss ip_status ip_status_detail 2>/dev/null || true
        set -e
        
        # 检查必要变量是否存在
        if [ -z "$file_alias" ] || [ -z "$file_overall_status" ]; then
            continue
        fi
        
        # 格式化输出
        local status_display=$(format_status "$file_overall_status")
        local latency_display=$(format_latency "$file_icmp_latency")
        local loss_display="${file_icmp_loss}%"
        local ip_status_display=$(format_ip_status "$file_ip_status" "$file_ip_status_detail")
        
        # 根据状态设置颜色
        local alias_color=""
        if [ "$file_overall_status" = "OK" ]; then
            alias_color="$GREEN"
        elif [ "$file_overall_status" = "WARN" ]; then
            alias_color="$YELLOW"
        else
            alias_color="$RED"
        fi
        
        # 使用 set +e 临时禁用错误退出，防止 printf 失败导致脚本退出
        set +e
        printf "${alias_color}%-20s${NC} %-15s %-8s %-12s %-10s %-20s\n" \
            "$file_alias" \
            "${file_cloud_provider:-N/A}" \
            "$status_display" \
            "$latency_display" \
            "$loss_display" \
            "$ip_status_display" || true
        set -e
        
        # 统计（使用 set +e 防止算术表达式失败）
        set +e
        case "$file_overall_status" in
            OK) ((ok_count++)) || true ;;
            WARN) ((warn_count++)) || true ;;
            FAIL) ((fail_count++)) || true ;;
        esac
        set -e
    done
    
    echo "--------------------------------------------------------------------------------"
    echo ""
    print_title "统计信息"
    echo -e "${GREEN}正常: $ok_count 台${NC}"
    if [ $warn_count -gt 0 ]; then
        echo -e "${YELLOW}警告: $warn_count 台${NC}"
    fi
    if [ $fail_count -gt 0 ]; then
        echo -e "${RED}失败: $fail_count 台${NC}"
    fi
    echo ""
}

# 保存检查结果到日志
save_check_log() {
    local result_files=("$@")
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    {
        echo "=========================================="
        echo "健康检查时间: $timestamp"
        echo "=========================================="
        echo ""
        
        for result_file in "${result_files[@]}"; do
            if [ ! -f "$result_file" ]; then
                continue
            fi
            
            source "$result_file"
            
            echo "[$alias]"
            echo "  IP: $ip"
            echo "  云厂商: ${cloud_provider:-N/A}"
            echo "  TCP端口($tcp_port): $tcp_status"
            echo "  ICMP延迟: ${icmp_latency}ms"
            echo "  ICMP丢包: ${icmp_loss}%"
            echo "  应用层: $app_status"
            echo "  IP状态: $ip_status ($ip_status_detail)"
            echo "  整体状态: $overall_status"
            echo "  检查耗时: ${duration}秒"
            echo ""
        done
    } > "$LAST_CHECK_LOG"
    
    print_info "检查结果已保存到: $LAST_CHECK_LOG"
}

# 批量健康检查（主函数）
batch_health_check() {
    local yaml_file=$1
    local parallel_mode=${2:-true}
    local max_parallel=${3:-10}
    
    print_title "开始健康检查"
    
    if [ ! -f "$yaml_file" ]; then
        print_error "配置文件不存在: $yaml_file"
        return 1
    fi
    
    if ! command -v yq >/dev/null 2>&1; then
        print_error "需要安装 yq 工具来解析 YAML 配置"
        print_info "安装方法: https://github.com/mikefarah/yq"
        return 1
    fi
    
    # 解析服务器列表
    local servers=$(parse_server_config "$yaml_file")
    if [ -z "$servers" ]; then
        print_error "未找到服务器配置"
        return 1
    fi
    
    local server_count=$(echo "$servers" | grep -c '"alias"' || echo "0")
    print_info "找到 $server_count 台服务器"
    
    if [ "$server_count" -eq 0 ]; then
        print_warn "没有可检查的服务器"
        return 0
    fi
    
    # 准备并发检查
    local check_pids=()
    local result_files=()
    local check_count=0
    
    print_info "开始检查（并发模式: $parallel_mode, 最大并发数: $max_parallel）..."
    echo ""
    
    # 处理每台服务器
    # yq 输出多行 JSON，需要转换为每行一个 JSON 对象
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
    
    local loop_count=0
    
    # 将 servers_processed 保存到临时文件，确保 while read 能正确读取所有行
    local temp_servers_file=$(mktemp)
    echo "$servers_processed" > "$temp_servers_file"
    
    # 将临时文件添加到全局清理列表（如果存在）
    if [ -n "${GLOBAL_TEMP_FILES:-}" ]; then
        GLOBAL_TEMP_FILES+=("$temp_servers_file")
    fi
    
    # 使用文件描述符 9 来隔离循环读取，防止后台任务消耗 stdin
    # 使用文件而不是 here-string，避免子 shell 问题
    while IFS= read -u 9 -r server_json || [ -n "$server_json" ]; do
        # 跳过空行
        if [ -z "$server_json" ]; then
            continue
        fi
        
        # 修复 loop_count++ 退出码问题：防止 set -e 捕获到非零退出码
        ((loop_count++)) || true
        
        if [ "$server_json" = "null" ]; then
            continue
        fi
        
        # 使用 set +e 避免 extract_server_field 失败导致脚本退出
        set +e
        local alias=$(extract_server_field "$server_json" "alias" 2>/dev/null)
        local ip=$(extract_server_field "$server_json" "ip" 2>/dev/null)
        local ssh_port=$(extract_server_field "$server_json" "ssh_port" 2>/dev/null)
        local ssh_user=$(extract_server_field "$server_json" "ssh_user" 2>/dev/null)
        local ssh_key=$(extract_server_field "$server_json" "ssh_key" 2>/dev/null)
        local cloud_provider=$(extract_server_field "$server_json" "cloud_provider" 2>/dev/null)
        set -e
        
        ssh_port=${ssh_port:-22}
        ssh_user=${ssh_user:-root}
        
        if [ -z "$alias" ] || [ -z "$ip" ]; then
            continue
        fi
        
        # 执行检查
        if [ "$parallel_mode" = "true" ]; then
            # 并行模式
            local result_file_path="$TEMP_DIR/${alias}.result"
            
            # 在主进程中先创建 fallback 文件（确保文件存在）
            
            {
                echo "alias=$alias"
                echo "ip=$ip"
                echo "cloud_provider=$cloud_provider"
                echo "tcp_status=FAIL"
                echo "tcp_port=443"
                echo "icmp_latency=0"
                echo "icmp_loss=100"
                echo "app_status=SKIP"
                echo "ip_status=UNKNOWN"
                echo "ip_status_detail="
                echo "overall_status=FAIL"
                echo "duration=0"
            } > "$result_file_path" 2>&1
            
            # 验证文件已创建
            if [ ! -f "$result_file_path" ]; then
                print_error "无法创建结果文件: $result_file_path"
                continue
            fi
            
            # 导出变量到子 shell
            local temp_dir_val="$TEMP_DIR"
            local alias_val="$alias"
            local ip_val="$ip"
            local cloud_provider_val="$cloud_provider"
            
            # 在后台执行检查（会更新结果文件）
            # 添加 < /dev/null 防止后台任务抢占终端输入
            (
                # 在子 shell 中禁用错误退出
                set +e
                # 重定向标准输入，防止抢占终端
                exec < /dev/null
                # 只重定向标准输出，保留标准错误用于调试
                exec 1> /dev/null
                
                # 使用传入的变量值
                TEMP_DIR="$temp_dir_val"
                result_file_path="$TEMP_DIR/${alias_val}.result"
                
                # 尝试执行检查（如果函数可用，会更新结果文件）
                if type -t check_single_server >/dev/null 2>&1; then
                    # 直接调用函数，确保使用 return 而不是 exit
                    check_single_server "$alias_val" "$ip_val" "$ssh_port" "$ssh_user" "$ssh_key" "$cloud_provider_val" >/dev/null 2>&1
                fi
            ) < /dev/null &
            local bg_pid=$!
            check_pids+=($bg_pid)
            
            # 将后台任务 PID 添加到全局清理列表（如果存在）
            if [ -n "${GLOBAL_BACKGROUND_PIDS:-}" ]; then
                GLOBAL_BACKGROUND_PIDS+=($bg_pid)
            fi
            
            # 结果文件路径
            result_files+=("$result_file_path")
            check_count=$((check_count + 1))
            
            # 控制并发数（只在达到最大并发数时等待）
            if [ $check_count -ge $max_parallel ]; then
                while [ $check_count -ge $max_parallel ]; do
                    if [ ${#check_pids[@]} -gt 0 ]; then
                        wait "${check_pids[0]}" 2>/dev/null
                        check_pids=("${check_pids[@]:1}")
                        check_count=$((check_count - 1))
                    else
                        # 如果没有 PID 了，直接退出循环
                        break
                    fi
                done
            fi
        else
            # 串行模式
            print_info "检查 [$alias] ($ip)..."
            local result_file=$(check_single_server "$alias" "$ip" "$ssh_port" "$ssh_user" "$ssh_key" "$cloud_provider")
            result_files+=("$result_file")
        fi
    done 9< "$temp_servers_file"
    
    # 关闭文件描述符 9（如果还打开的话）
    exec 9<&-
    
    # 清理临时文件
    rm -f "$temp_servers_file"
    
    # 等待所有并行任务完成（确保主进程在所有子进程完成前不退出）
    if [ "$parallel_mode" = "true" ] && [ ${#check_pids[@]} -gt 0 ]; then
        print_info "等待所有检查任务完成..."
        
        # 使用 wait 等待所有后台进程，确保主进程不会提前退出
        for pid in "${check_pids[@]}"; do
            # 检查进程是否还在运行
            if kill -0 "$pid" 2>/dev/null; then
                wait "$pid" 2>/dev/null
            fi
        done
        
        # 额外等待，确保所有子进程完全退出
        sleep 1
    fi
    
    # 等待所有结果文件写入完成（并行模式需要额外等待）
    # 确保所有子进程完成后再读取结果文件
    if [ "$parallel_mode" = "true" ]; then
        # 等待所有后台进程完全退出（额外等待时间）
        if [ ${#check_pids[@]} -gt 0 ]; then
            sleep 2
        else
            sleep 1
        fi
        
        # 过滤掉不存在的文件
        local valid_result_files=()
        for result_file in "${result_files[@]}"; do
            if [ -f "$result_file" ] && [ -s "$result_file" ]; then
                valid_result_files+=("$result_file")
            fi
        done
        result_files=("${valid_result_files[@]}")
        
        if [ ${#result_files[@]} -eq 0 ]; then
            print_warn "没有找到任何有效的结果文件"
            print_info "提示: 使用 LOG_LEVEL=debug ./main.sh health 查看详细日志"
        fi
    else
        sleep 1
    fi
    
    # 生成报告
    echo ""
    generate_health_report "${result_files[@]}"
    
    # 保存日志
    save_check_log "${result_files[@]}"
    
    # 检查是否有失败的节点
    local failed_servers=()
    for result_file in "${result_files[@]}"; do
        if [ -f "$result_file" ]; then
            source "$result_file" 2>/dev/null
            if [ "$overall_status" = "FAIL" ]; then
                failed_servers+=("$alias")
            fi
        fi
    done
    
    # 如果有失败的节点，提示用户
    if [ ${#failed_servers[@]} -gt 0 ]; then
        echo ""
        print_warn "检测到 ${#failed_servers[@]} 台服务器状态异常:"
        for server in "${failed_servers[@]}"; do
            echo "  - $server"
        done
        echo ""
        echo -e "${CYAN}请选择操作:${NC}"
        echo "  [1] 重启失败的服务器上的 Xray 服务"
        echo "  [2] 重新部署失败的服务器（完整部署）"
        echo "  [3] 仅查看失败详情，不执行操作"
        echo ""
        echo -ne "${YELLOW}请输入选项 [1-3，默认3]: ${NC}"
        read -r action_choice
        
        if [ "$action_choice" = "1" ]; then
            # 重启服务
            print_info "开始重启失败的服务器上的 Xray 服务..."
            local restart_success=0
            local restart_failed=0
            
            for failed_server in "${failed_servers[@]}"; do
                # 从配置文件中获取服务器信息
                local server_json=$(parse_server_config "$yaml_file" "$failed_server")
                if [ -z "$server_json" ]; then
                    print_warn "[$failed_server] 未找到服务器配置，跳过"
                    continue
                fi
                
                local server_ip=$(extract_server_field "$server_json" "ip")
                local ssh_port=$(extract_server_field "$server_json" "ssh_port")
                ssh_port=${ssh_port:-22}
                local ssh_user=$(extract_server_field "$server_json" "ssh_user")
                ssh_user=${ssh_user:-root}
                local ssh_key=$(extract_server_field "$server_json" "ssh_key")
                
                if [ -z "$server_ip" ]; then
                    print_warn "[$failed_server] 无法获取服务器 IP，跳过"
                    continue
                fi
                
                print_info "[$failed_server] 正在重启 Xray 服务..."
                local ssh_cmd=$(build_ssh_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
                
                if $ssh_cmd "systemctl restart xray" >/dev/null 2>&1; then
                    sleep 2
                    if $ssh_cmd "systemctl is-active --quiet xray" >/dev/null 2>&1; then
                        print_success "[$failed_server] Xray 服务重启成功"
                        ((restart_success++))
                    else
                        print_warn "[$failed_server] Xray 服务重启后未运行，请检查配置"
                        ((restart_failed++))
                    fi
                else
                    print_error "[$failed_server] 无法连接到服务器或重启失败"
                    ((restart_failed++))
                fi
            done
            
            echo ""
            print_info "重启操作完成: 成功 $restart_success 台，失败 $restart_failed 台"
            if [ $restart_success -gt 0 ]; then
                echo ""
                print_info "建议等待 10 秒后重新运行健康检查: ./main.sh health"
            fi
            
        elif [ "$action_choice" = "2" ]; then
            # 重新部署
            print_info "开始重新部署失败的服务器..."
            print_warn "此操作将重新部署以下服务器:"
            for server in "${failed_servers[@]}"; do
                echo "  - $server"
            done
            echo ""
            echo -ne "${YELLOW}确认继续？[y/N]: ${NC}"
            read -r confirm_deploy
            if [[ "$confirm_deploy" =~ ^[Yy]$ ]]; then
                # 调用 multi_server.sh 的部署功能
                if [ -f "$SCRIPT_DIR/modules/multi_server.sh" ]; then
                    source "$SCRIPT_DIR/modules/multi_server.sh"
                    for failed_server in "${failed_servers[@]}"; do
                        print_info "正在部署: $failed_server"
                        batch_deploy "$yaml_file" "$SCRIPT_DIR" "$failed_server"
                    done
                else
                    print_error "未找到 multi_server.sh 模块"
                    print_info "请手动执行: ./main.sh deploy -s <server_alias>"
                fi
            else
                print_info "已取消部署操作"
            fi
        else
            print_info "已取消操作"
            print_info "如需手动处理，可以使用以下命令:"
            echo "  # 重启服务: ssh user@server_ip 'systemctl restart xray'"
            echo "  # 重新部署: ./main.sh deploy -s <server_alias>"
            echo "  # 查看状态: ./main.sh status"
        fi
    fi
    
    # 清理临时文件
    rm -rf "$TEMP_DIR" 2>/dev/null
    
    return 0
}

# 如果直接运行此脚本
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    if [ $# -lt 1 ]; then
        echo "用法: $0 <config_file> [parallel_mode] [max_parallel]"
        echo "  config_file: 服务器配置文件路径（如 configs/servers.yaml）"
        echo "  parallel_mode: 是否并行检查 (true/false, 默认: true)"
        echo "  max_parallel: 最大并发数 (默认: 10)"
        exit 1
    fi
    
    batch_health_check "$1" "${2:-true}" "${3:-10}"
fi
