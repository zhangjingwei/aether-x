#!/bin/bash

# 订阅管理模块
# 根据健康检查结果自动生成订阅链接，支持多种分发方式

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
DIST_DIR="dist"
LOG_DIR="logs"
SUBSCRIPTION_BASE_DIR="$DIST_DIR"
DEFAULT_XRAY_PORT=443

# 确保目录存在
mkdir -p "$DIST_DIR"
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
                yq eval ".servers[] | select(.alias == \"$server_alias\")" "$yaml_file" -o json 2>/dev/null
            else
                yq eval '.servers[]' "$yaml_file" -o json 2>/dev/null
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
        
        # 优先使用 jq 解析（如果可用）
        if command -v jq >/dev/null 2>&1; then
            local value=$(echo "$server_json" | jq -r ".$field // empty" 2>/dev/null)
            if [ -n "$value" ] && [ "$value" != "null" ]; then
                echo "$value"
                return 0
            fi
        fi
        
        # 使用 yq 解析（如果可用）
        if command -v yq >/dev/null 2>&1; then
            local value=$(echo "$server_json" | yq eval ".$field // empty" 2>/dev/null)
            if [ -n "$value" ] && [ "$value" != "null" ]; then
                echo "$value"
                return 0
            fi
        fi
        
        # 备选方案：使用 grep 和 cut
        local value=$(echo "$server_json" | grep -o "\"$field\":\"[^\"]*\"" | cut -d'"' -f4)
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
        
        # 尝试匹配数字值
        value=$(echo "$server_json" | grep -o "\"$field\":[0-9]*" | cut -d':' -f2 | tr -d ' ')
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
        
        return 1
    }
fi

# URL编码函数
url_encode() {
    local string="$1"
    local encoded=""
    local i=0
    local len=${#string}
    
    while [ $i -lt $len ]; do
        local char="${string:$i:1}"
        case "$char" in
            [a-zA-Z0-9.~_-])
                encoded="${encoded}${char}"
                ;;
            *)
                encoded="${encoded}$(printf '%%%02X' "'$char")"
                ;;
        esac
        ((i++))
    done
    
    echo "$encoded"
}

# 从远程服务器读取Xray配置信息
get_remote_xray_config() {
    local ssh_cmd=$1
    local config_path="/usr/local/etc/xray/config.json"
    
    # 读取配置文件
    local config_json=$($ssh_cmd "cat $config_path 2>/dev/null" 2>/dev/null)
    
    if [ -z "$config_json" ]; then
        return 1
    fi
    
    # 解析配置
    local uuid=$(echo "$config_json" | grep -o '"id": "[^"]*"' | head -1 | cut -d'"' -f4)
    local port=$(echo "$config_json" | grep -o '"port": [0-9]*' | head -1 | cut -d':' -f2 | tr -d ' ')
    local private_key=$(echo "$config_json" | grep -o '"privateKey": "[^"]*"' | head -1 | cut -d'"' -f4)
    local server_name=$(echo "$config_json" | grep -o '"serverNames": \[[^]]*\]' | grep -o '"[^"]*"' | head -1 | cut -d'"' -f2)
    local short_id=$(echo "$config_json" | grep -o '"shortIds": \[[^]]*\]' | grep -o '"[^"]*"' | head -1 | cut -d'"' -f2)
    local service_name=$(echo "$config_json" | grep -o '"serviceName": "[^"]*"' | head -1 | cut -d'"' -f4)
    local network=$(echo "$config_json" | grep -o '"network": "[^"]*"' | head -1 | cut -d'"' -f4)
    
    # 如果没有找到network，默认为grpc
    network=${network:-grpc}
    
    # 如果找到了privateKey，需要转换为publicKey
    local public_key=""
    if [ -n "$private_key" ]; then
        # 尝试使用xray获取public key
        public_key=$($ssh_cmd "/usr/local/bin/xray x25519 -i $private_key 2>/dev/null | grep -i public | awk '{print \$NF}'" 2>/dev/null)
    fi
    
    # 如果无法获取public key，尝试从配置中读取
    if [ -z "$public_key" ]; then
        # 某些配置可能直接存储publicKey
        public_key=$(echo "$config_json" | grep -o '"publicKey": "[^"]*"' | head -1 | cut -d'"' -f4)
    fi
    
    # 设置默认值
    port=${port:-$DEFAULT_XRAY_PORT}
    server_name=${server_name:-www.microsoft.com}
    service_name=${service_name:-GunService}
    
    echo "${uuid}|${port}|${public_key}|${server_name}|${short_id}|${service_name}|${network}"
    return 0
}

# 从远程服务器拉取info文件到本地
fetch_remote_info_file() {
    local node_alias=$1
    local ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local config_dir="configs"
    
    local remote_info_path="/usr/local/etc/xray/config.info"
    local local_info_file="$config_dir/${node_alias}.info"
    
    # 构建SSH命令
    local ssh_cmd=$(build_ssh_cmd "$ip" "$ssh_port" "$ssh_user" "$ssh_key")
    
    # 检查远程info文件是否存在
    if ! timeout 5 $ssh_cmd "test -f $remote_info_path" >/dev/null 2>&1; then
        return 1
    fi
    
    # 构建SCP命令
    local scp_cmd="scp -P $ssh_port"
    scp_cmd="$scp_cmd -o StrictHostKeyChecking=no"
    scp_cmd="$scp_cmd -o ConnectTimeout=10"
    scp_cmd="$scp_cmd -o BatchMode=yes"
    scp_cmd="$scp_cmd -o UserKnownHostsFile=/dev/null"
    
    if [ -n "$ssh_key" ]; then
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        if [ -f "$ssh_key" ]; then
            scp_cmd="$scp_cmd -i $ssh_key"
        fi
    fi
    
    # 确保本地configs目录存在
    mkdir -p "$config_dir"
    
    # 从远程拉取info文件
    if $scp_cmd "$ssh_user@$ip:$remote_info_path" "$local_info_file" >/dev/null 2>&1; then
        # 在info文件开头添加服务器别名，方便后续查找
        if ! grep -q "服务器别名\|Server Alias\|Alias:" "$local_info_file" 2>/dev/null; then
            # 在文件开头添加别名信息
            local temp_file=$(mktemp)
            echo "# 服务器别名: $node_alias" > "$temp_file"
            cat "$local_info_file" >> "$temp_file"
            mv "$temp_file" "$local_info_file"
        fi
        print_info "已从服务端拉取info文件: $node_alias"
        return 0
    else
        return 1
    fi
}

# 从本地info文件读取配置信息
get_local_config_info() {
    local alias=$1
    local config_dir="configs"
    
    # 查找对应的info文件
    local info_file=$(find "$config_dir" -name "*.info" -type f 2>/dev/null | xargs grep -l "$alias" 2>/dev/null | head -1)
    
    if [ -z "$info_file" ]; then
        return 1
    fi
    
    # 解析info文件
    local uuid=$(grep "UUID:" "$info_file" | awk '{print $2}')
    local public_key=$(grep "Public Key:" "$info_file" | awk '{print $3}')
    local short_id=$(grep "ShortID:" "$info_file" | awk '{print $2}')
    local server_name=$(grep "Server Name:" "$info_file" | awk '{print $3}')
    local service_name=$(grep "gRPC ServiceName:" "$info_file" | awk '{print $2}')
    
    if [ -z "$uuid" ] || [ -z "$public_key" ]; then
        return 1
    fi
    
    # 从对应的json文件获取端口
    local json_file="${info_file%.info}.json"
    local port=$DEFAULT_XRAY_PORT
    if [ -f "$json_file" ]; then
        port=$(grep -o '"port": [0-9]*' "$json_file" | head -1 | cut -d':' -f2 | tr -d ' ')
        port=${port:-$DEFAULT_XRAY_PORT}
    fi
    
    echo "${uuid}|${port}|${public_key}|${server_name}|${short_id}|${service_name}|grpc"
    return 0
}

# 生成VLESS URL
generate_vless_url() {
    local alias=$1
    local ip=$2
    local port=$3
    local uuid=$4
    local public_key=$5
    local server_name=$6
    local short_id=$7
    local service_name=$8
    local network=${9:-grpc}
    
    # URL编码参数
    local encoded_sni=$(url_encode "$server_name")
    local encoded_service=$(url_encode "$service_name")
    
    # 构建VLESS URL
    # 格式: vless://uuid@ip:port?type=grpc&security=reality&sni=server_name&pbk=public_key&sid=short_id&spx=%2F&serviceName=service_name&fp=chrome#alias
    
    local url="vless://${uuid}@${ip}:${port}?type=${network}&security=reality"
    url="${url}&sni=${encoded_sni}"
    url="${url}&pbk=${public_key}"
    
    if [ -n "$short_id" ]; then
        url="${url}&sid=${short_id}"
    fi
    
    url="${url}&spx=%2F"
    
    if [ "$network" = "grpc" ] && [ -n "$service_name" ]; then
        url="${url}&serviceName=${encoded_service}"
    fi
    
    url="${url}&fp=chrome"
    url="${url}#$(url_encode "$alias")"
    
    echo "$url"
}

# 读取健康检查日志，获取OK状态的节点和IP地址
get_healthy_nodes() {
    local check_log=$1
    
    if [ ! -f "$check_log" ]; then
        print_warn "健康检查日志不存在: $check_log"
        return 1
    fi
    
    local healthy_nodes=()
    
    # 解析日志文件，提取状态为OK的节点
    local current_alias=""
    local current_status=""
    local current_ip=""
    
    while IFS= read -r line; do
        # 检查是否是节点开始标记 [alias]
        if echo "$line" | grep -qE '^\s*\[.*\]\s*$'; then
            # 保存上一个节点的信息
            if [ -n "$current_alias" ] && [ "$current_status" = "OK" ]; then
                healthy_nodes+=("$current_alias|$current_ip")
            fi
            current_alias=$(echo "$line" | sed 's/^\s*\[\(.*\)\]\s*$/\1/')
            current_status=""
            current_ip=""
        elif [ -n "$current_alias" ]; then
            # 提取IP地址
            if echo "$line" | grep -qE "^\s*IP:"; then
                current_ip=$(echo "$line" | awk -F':|=' '{print $2}' | tr -d ' ')
            fi
            # 检查整体状态行
            if echo "$line" | grep -qE "整体状态|overall_status"; then
                current_status=$(echo "$line" | awk -F':|=' '{print $2}' | tr -d ' ')
            fi
        fi
    done < "$check_log"
    
    # 保存最后一个节点
    if [ -n "$current_alias" ] && [ "$current_status" = "OK" ]; then
        healthy_nodes+=("$current_alias|$current_ip")
    fi
    
    # 输出健康节点列表（格式：alias|ip）
    if [ ${#healthy_nodes[@]} -gt 0 ]; then
        printf '%s\n' "${healthy_nodes[@]}"
        return 0
    else
        return 1
    fi
}

# 生成订阅内容
generate_subscription() {
    local yaml_file=$1
    local check_log=$2
    local output_file=$3
    
    if [ ! -f "$yaml_file" ]; then
        print_error "配置文件不存在: $yaml_file"
        return 1
    fi
    
    # 获取健康节点列表（格式：alias|ip）
    print_info "读取健康检查结果..."
    local healthy_nodes_raw=($(get_healthy_nodes "$check_log" 2>/dev/null))
    
    # 解析健康节点，提取别名和IP
    declare -A node_ip_map
    local healthy_nodes=()
    
    for node_info in "${healthy_nodes_raw[@]}"; do
        if echo "$node_info" | grep -q "|"; then
            local node_alias=$(echo "$node_info" | cut -d'|' -f1)
            local node_ip=$(echo "$node_info" | cut -d'|' -f2)
            if [ -n "$node_alias" ]; then
                healthy_nodes+=("$node_alias")
                if [ -n "$node_ip" ]; then
                    node_ip_map["$node_alias"]="$node_ip"
                fi
            fi
        else
            # 兼容旧格式（只有别名）
            if [ -n "$node_info" ]; then
                healthy_nodes+=("$node_info")
            fi
        fi
    done
    
    if [ ${#healthy_nodes[@]} -eq 0 ]; then
        print_warn "未找到健康节点，将使用所有节点"
        # 如果没有健康检查日志，使用所有节点
        local servers=$(parse_server_config "$yaml_file")
        while IFS= read -r server_json; do
            [ -z "$server_json" ] || [ "$server_json" = "null" ] && continue
            local alias=$(extract_server_field "$server_json" "alias")
            if [ -n "$alias" ]; then
                healthy_nodes+=("$alias")
            fi
        done <<< "$servers"
    fi
    
    # 去重
    if [ ${#healthy_nodes[@]} -gt 0 ]; then
        local unique_nodes=($(printf '%s\n' "${healthy_nodes[@]}" | sort -u))
        healthy_nodes=("${unique_nodes[@]}")
    fi
    
    if [ ${#healthy_nodes[@]} -eq 0 ]; then
        print_error "未找到任何节点"
        return 1
    fi
    
    print_info "找到 ${#healthy_nodes[@]} 个健康节点"
    
    # 生成VLESS URL列表
    local vless_urls=()
    local success_count=0
    local fail_count=0
    
    local servers=$(parse_server_config "$yaml_file")
    
    for node_alias in "${healthy_nodes[@]}"; do
        # 使用yq精确匹配服务器配置
        local server_json=$(parse_server_config "$yaml_file" "$node_alias")
        
        if [ -z "$server_json" ] || [ "$server_json" = "null" ]; then
            # 如果yq失败，尝试grep方式
            server_json=$(echo "$servers" | grep -A 10 "\"alias\":\"$node_alias\"" | head -10)
        fi
        
        local ip=""
        local ssh_port=""
        local ssh_user=""
        local ssh_key=""
        
        # 优先从健康检查日志中获取IP
        if [ -n "${node_ip_map[$node_alias]}" ]; then
            ip="${node_ip_map[$node_alias]}"
        fi
        
        # 如果日志中没有IP，从配置文件中读取
        if [ -z "$ip" ] && [ -n "$server_json" ]; then
            ip=$(extract_server_field "$server_json" "ip")
        fi
        
        # 从配置文件读取其他信息
        if [ -n "$server_json" ]; then
            ssh_port=$(extract_server_field "$server_json" "ssh_port")
            ssh_user=$(extract_server_field "$server_json" "ssh_user")
            ssh_key=$(extract_server_field "$server_json" "ssh_key")
        fi
        
        ssh_port=${ssh_port:-22}
        ssh_user=${ssh_user:-root}
        
        if [ -z "$ip" ]; then
            print_warn "节点 $node_alias 缺少IP地址"
            ((fail_count++))
            continue
        fi
        
        print_info "处理节点: $node_alias ($ip)"
        
        # 尝试获取配置信息
        local config_info=""
        
        # 方法1: 从本地info文件读取
        config_info=$(get_local_config_info "$node_alias")
        
        # 方法2: 如果本地没有，从服务端拉取info文件
        if [ -z "$config_info" ] || echo "$config_info" | grep -q "^|"; then
            local ssh_cmd=$(build_ssh_cmd "$ip" "$ssh_port" "$ssh_user" "$ssh_key")
            if timeout 5 $ssh_cmd "echo test" >/dev/null 2>&1; then
                # 尝试从服务端拉取info文件
                if fetch_remote_info_file "$node_alias" "$ip" "$ssh_port" "$ssh_user" "$ssh_key"; then
                    # 拉取成功后，再次尝试从本地读取
                    config_info=$(get_local_config_info "$node_alias")
                fi
            fi
        fi
        
        # 方法3: 如果仍然没有，从远程服务器读取配置文件
        if [ -z "$config_info" ] || echo "$config_info" | grep -q "^|"; then
            local ssh_cmd=$(build_ssh_cmd "$ip" "$ssh_port" "$ssh_user" "$ssh_key")
            if timeout 5 $ssh_cmd "echo test" >/dev/null 2>&1; then
                config_info=$(get_remote_xray_config "$ssh_cmd")
            fi
        fi
        
        if [ -z "$config_info" ] || echo "$config_info" | grep -q "^|"; then
            print_warn "无法获取节点 $node_alias 的配置信息，跳过"
            ((fail_count++))
            continue
        fi
        
        # 解析配置信息
        local uuid=$(echo "$config_info" | cut -d'|' -f1)
        local port=$(echo "$config_info" | cut -d'|' -f2)
        local public_key=$(echo "$config_info" | cut -d'|' -f3)
        local server_name=$(echo "$config_info" | cut -d'|' -f4)
        local short_id=$(echo "$config_info" | cut -d'|' -f5)
        local service_name=$(echo "$config_info" | cut -d'|' -f6)
        local network=$(echo "$config_info" | cut -d'|' -f7)
        
        if [ -z "$uuid" ] || [ -z "$public_key" ]; then
            print_warn "节点 $node_alias 配置信息不完整，跳过"
            ((fail_count++))
            continue
        fi
        
        # 生成VLESS URL
        local vless_url=$(generate_vless_url "$node_alias" "$ip" "$port" "$uuid" \
            "$public_key" "$server_name" "$short_id" "$service_name" "$network")
        
        vless_urls+=("$vless_url")
        ((success_count++))
        print_success "已生成: $node_alias"
    done
    
    if [ ${#vless_urls[@]} -eq 0 ]; then
        print_error "未能生成任何订阅链接"
        return 1
    fi
    
    # 将URL列表转换为Base64编码
    print_info "编码订阅内容..."
    local subscription_content=$(printf '%s\n' "${vless_urls[@]}")
    local encoded_content=$(echo -n "$subscription_content" | base64 -w 0 2>/dev/null || \
        echo -n "$subscription_content" | base64 | tr -d '\n')
    
    # 保存到文件
    echo "$encoded_content" > "$output_file"
    
    print_success "订阅文件已生成: $output_file"
    print_info "包含 ${#vless_urls[@]} 个节点"
    print_info "成功: $success_count 个，失败: $fail_count 个"
    
    # 同时保存原始URL列表（用于调试）
    local raw_file="${output_file%.txt}.raw.txt"
    printf '%s\n' "${vless_urls[@]}" > "$raw_file"
    print_info "原始URL列表已保存: $raw_file"
    
    return 0
}

# 生成随机文件名
generate_random_filename() {
    local prefix=${1:-"sub"}
    local extension=${2:-"txt"}
    local random_str=$(openssl rand -hex 4 2>/dev/null || \
        cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -1)
    echo "${prefix}_${random_str}.${extension}"
}

# 分发到AWS S3
distribute_to_s3() {
    local file_path=$1
    local s3_bucket=$2
    local s3_key=${3:-""}
    
    if [ -z "$s3_bucket" ]; then
        print_error "S3 bucket名称不能为空"
        return 1
    fi
    
    if ! command -v aws >/dev/null 2>&1; then
        print_error "未安装 AWS CLI，无法上传到S3"
        print_info "安装方法: https://aws.amazon.com/cli/"
        return 1
    fi
    
    if [ -z "$s3_key" ]; then
        s3_key=$(basename "$file_path")
    fi
    
    print_info "上传到 S3: s3://${s3_bucket}/${s3_key}"
    
    if aws s3 cp "$file_path" "s3://${s3_bucket}/${s3_key}" --acl public-read 2>/dev/null; then
        local s3_url="https://${s3_bucket}.s3.amazonaws.com/${s3_key}"
        print_success "上传成功: $s3_url"
        echo "$s3_url"
        return 0
    else
        print_error "上传失败"
        return 1
    fi
}

# 分发到GitHub Pages
distribute_to_github() {
    local file_path=$1
    local repo_owner=$2
    local repo_name=$3
    local github_token=$4
    local branch=${5:-"gh-pages"}
    local path=${6:-""}
    
    if [ -z "$repo_owner" ] || [ -z "$repo_name" ] || [ -z "$github_token" ]; then
        print_error "GitHub配置不完整"
        return 1
    fi
    
    if ! command -v curl >/dev/null 2>&1; then
        print_error "未安装 curl，无法上传到GitHub"
        return 1
    fi
    
    local filename=$(basename "$file_path")
    if [ -n "$path" ]; then
        filename="${path}/${filename}"
    fi
    
    print_info "上传到 GitHub: ${repo_owner}/${repo_name}/${filename}"
    
    # 读取文件内容并Base64编码
    local file_content=$(cat "$file_path" | base64 -w 0 2>/dev/null || \
        cat "$file_path" | base64 | tr -d '\n')
    
    # 获取文件SHA（如果存在）
    local file_sha=""
    local get_url="https://api.github.com/repos/${repo_owner}/${repo_name}/contents/${filename}"
    local existing_file=$(curl -s -H "Authorization: token $github_token" "$get_url")
    if echo "$existing_file" | grep -q '"sha"'; then
        file_sha=$(echo "$existing_file" | grep -o '"sha": "[^"]*"' | cut -d'"' -f4)
    fi
    
    # 构建提交数据
    local commit_message="Update subscription: $(date '+%Y-%m-%d %H:%M:%S')"
    local json_data=$(cat << EOF
{
  "message": "$commit_message",
  "content": "$file_content",
  "branch": "$branch"
EOF
)
    
    if [ -n "$file_sha" ]; then
        json_data="${json_data},\n  \"sha\": \"$file_sha\""
    fi
    json_data="${json_data}\n}"
    
    # 上传文件
    local upload_url="https://api.github.com/repos/${repo_owner}/${repo_name}/contents/${filename}"
    local response=$(echo -e "$json_data" | curl -s -X PUT \
        -H "Authorization: token $github_token" \
        -H "Content-Type: application/json" \
        -d @- \
        "$upload_url")
    
    if echo "$response" | grep -q '"content"'; then
        local github_url="https://${repo_owner}.github.io/${repo_name}/${filename}"
        print_success "上传成功: $github_url"
        echo "$github_url"
        return 0
    else
        print_error "上传失败: $(echo "$response" | grep -o '"message": "[^"]*"' | head -1)"
        return 1
    fi
}

# 分发到VPS Nginx目录
distribute_to_vps() {
    local file_path=$1
    local server_ip=$2
    local ssh_port=$3
    local ssh_user=$4
    local ssh_key=$5
    local remote_path=$6
    
    if [ -z "$server_ip" ] || [ -z "$remote_path" ]; then
        print_error "VPS配置不完整"
        return 1
    fi
    
    ssh_port=${ssh_port:-22}
    ssh_user=${ssh_user:-root}
    
    print_info "上传到 VPS: ${ssh_user}@${server_ip}:${remote_path}"
    
    local scp_cmd="scp -P $ssh_port"
    scp_cmd="$scp_cmd -o StrictHostKeyChecking=no"
    scp_cmd="$scp_cmd -o ConnectTimeout=10"
    scp_cmd="$scp_cmd -o BatchMode=yes"
    scp_cmd="$scp_cmd -o UserKnownHostsFile=/dev/null"
    
    if [ -n "$ssh_key" ]; then
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        if [ -f "$ssh_key" ]; then
            scp_cmd="$scp_cmd -i $ssh_key"
        fi
    fi
    
    scp_cmd="$scp_cmd $file_path ${ssh_user}@${server_ip}:${remote_path}"
    
    if $scp_cmd >/dev/null 2>&1; then
        # 设置文件权限
        local ssh_cmd=$(build_ssh_cmd "$server_ip" "$ssh_port" "$ssh_user" "$ssh_key")
        $ssh_cmd "chmod 644 ${remote_path}" >/dev/null 2>&1
        
        print_success "上传成功"
        echo "http://${server_ip}/$(basename "$remote_path")"
        return 0
    else
        print_error "上传失败"
        return 1
    fi
}

# 主函数：生成并分发订阅
generate_and_distribute_subscription() {
    local yaml_file=$1
    local check_log=${2:-""}
    local distribution_method=${3:-""}
    local distribution_config=${4:-""}
    
    # 生成随机文件名
    local random_filename=$(generate_random_filename "sub" "txt")
    local subscription_file="$SUBSCRIPTION_BASE_DIR/$random_filename"
    
    # 生成订阅
    if ! generate_subscription "$yaml_file" "$check_log" "$subscription_file"; then
        return 1
    fi
    
    echo ""
    
    # 如果需要分发
    if [ -n "$distribution_method" ]; then
        print_title "分发订阅"
        
        local distribution_url=""
        
        case "$distribution_method" in
            s3)
                # S3配置格式: bucket:key
                local s3_bucket=$(echo "$distribution_config" | cut -d':' -f1)
                local s3_key=$(echo "$distribution_config" | cut -d':' -f2)
                distribution_url=$(distribute_to_s3 "$subscription_file" "$s3_bucket" "$s3_key")
                ;;
            github)
                # GitHub配置格式: owner:repo:token:branch:path
                local owner=$(echo "$distribution_config" | cut -d':' -f1)
                local repo=$(echo "$distribution_config" | cut -d':' -f2)
                local token=$(echo "$distribution_config" | cut -d':' -f3)
                local branch=$(echo "$distribution_config" | cut -d':' -f4)
                local path=$(echo "$distribution_config" | cut -d':' -f5)
                branch=${branch:-gh-pages}
                distribution_url=$(distribute_to_github "$subscription_file" "$owner" "$repo" "$token" "$branch" "$path")
                ;;
            vps)
                # VPS配置格式: ip:port:user:key:remote_path
                local vps_ip=$(echo "$distribution_config" | cut -d':' -f1)
                local vps_port=$(echo "$distribution_config" | cut -d':' -f2)
                local vps_user=$(echo "$distribution_config" | cut -d':' -f3)
                local vps_key=$(echo "$distribution_config" | cut -d':' -f4)
                local vps_path=$(echo "$distribution_config" | cut -d':' -f5)
                distribution_url=$(distribute_to_vps "$subscription_file" "$vps_ip" "$vps_port" "$vps_user" "$vps_key" "$vps_path")
                ;;
            *)
                print_warn "未知的分发方式: $distribution_method"
                ;;
        esac
        
        if [ -n "$distribution_url" ]; then
            echo ""
            print_success "订阅链接: $distribution_url"
        fi
    else
        print_info "订阅文件已保存: $subscription_file"
        print_info "如需分发，请使用相应的分发函数"
    fi
    
    return 0
}

# 如果直接运行此脚本
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    if [ $# -lt 1 ]; then
        echo "用法: $0 <config_file> [check_log] [distribution_method] [distribution_config]"
        echo ""
        echo "参数:"
        echo "  config_file: 服务器配置文件路径（如 configs/servers.yaml）"
        echo "  check_log: 健康检查日志路径（默认: logs/last_check.log）"
        echo "  distribution_method: 分发方式 (s3/github/vps)"
        echo "  distribution_config: 分发配置"
        echo ""
        echo "分发配置格式:"
        echo "  S3: bucket:key"
        echo "  GitHub: owner:repo:token:branch:path"
        echo "  VPS: ip:port:user:key:remote_path"
        echo ""
        echo "示例:"
        echo "  $0 configs/servers.yaml"
        echo "  $0 configs/servers.yaml logs/last_check.log s3 my-bucket:subscription.txt"
        echo "  $0 configs/servers.yaml logs/last_check.log github owner:repo:token:gh-pages:sub"
        exit 1
    fi
    
    generate_and_distribute_subscription "$1" "${2:-}" "$3" "$4"
fi
