#!/bin/bash

# 配置生成模块
# 生成 VLESS + REALITY + gRPC 配置，符合 Xray-core 最新规范

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
fi

# 生成 UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    elif [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        # 使用 openssl 生成 UUID
        openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
    fi
}

# 生成 REALITY 密钥对（使用 xray x25519）
generate_reality_keys() {
    local xray_bin=${1:-"/usr/local/bin/xray"}
    
    # 尝试多个可能的路径
    local xray_paths=("$xray_bin" "xray" "/usr/bin/xray" "/usr/local/bin/xray")
    local found_xray=""
    
    for path in "${xray_paths[@]}"; do
        if command -v "$path" >/dev/null 2>&1 || [ -f "$path" ]; then
            found_xray="$path"
            break
        fi
    done
    
    if [ -z "$found_xray" ]; then
        print_error "无法找到 xray 命令，无法生成 REALITY 密钥"
        return 1
    fi
    
    # 使用 xray x25519 生成密钥对
    local key_output=$("$found_xray" x25519 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$key_output" ]; then
        print_error "生成 REALITY 密钥失败"
        return 1
    fi
    
    # 解析输出（兼容不同格式）
    local private_key=$(echo "$key_output" | grep -iE "private|私钥" | awk '{print $NF}' | head -1)
    local public_key=$(echo "$key_output" | grep -iE "public|公钥" | awk '{print $NF}' | head -1)
    
    # 如果上面的解析失败，尝试其他格式
    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        private_key=$(echo "$key_output" | sed -n '1p' | awk '{print $2}')
        public_key=$(echo "$key_output" | sed -n '2p' | awk '{print $2}')
    fi
    
    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        print_error "解析 REALITY 密钥失败"
        print_error "xray 输出: $key_output"
        return 1
    fi
    
    echo "$private_key|$public_key"
    return 0
}

# 生成 ShortID（8位十六进制）
generate_short_id() {
    openssl rand -hex 4
}

# 随机选择伪装目标
random_sni_target() {
    local targets=(
        "www.microsoft.com"
        "www.yahoo.com"
        "www.google.com"
        "www.apple.com"
        "www.amazon.com"
        "www.facebook.com"
        "www.twitter.com"
        "www.github.com"
        "www.cloudflare.com"
        "www.bing.com"
    )
    
    local count=${#targets[@]}
    local index=$((RANDOM % count))
    echo "${targets[$index]}"
}

# 随机生成 gRPC ServiceName
random_grpc_service_name() {
    local prefixes=("GunService" "grpc" "service" "api" "rpc" "stream")
    local suffixes=("Stream" "Service" "API" "RPC" "Data" "Proxy")
    
    local prefix=${prefixes[$((RANDOM % ${#prefixes[@]}))]}
    local suffix=${suffixes[$((RANDOM % ${#suffixes[@]}))]}
    
    # 随机选择是否使用后缀
    if [ $((RANDOM % 2)) -eq 0 ]; then
        echo "${prefix}${suffix}"
    else
        echo "$prefix"
    fi
}

# 验证 JSON 格式
validate_json() {
    local json_file=$1
    
    if [ ! -f "$json_file" ]; then
        print_error "文件不存在: $json_file"
        return 1
    fi
    
    # 使用 jq 验证（如果可用）
    if command -v jq >/dev/null 2>&1; then
        if jq empty "$json_file" >/dev/null 2>&1; then
            return 0
        else
            print_error "JSON 格式验证失败"
            jq . "$json_file" 2>&1 | head -10
            return 1
        fi
    fi
    
    # 使用 Python 验证（如果可用）
    if command -v python3 >/dev/null 2>&1; then
        if python3 -m json.tool "$json_file" >/dev/null 2>&1; then
            return 0
        else
            print_error "JSON 格式验证失败"
            return 1
        fi
    fi
    
    # 简单检查：确保是有效的 JSON 结构
    if grep -q '{' "$json_file" && grep -q '}' "$json_file"; then
        print_warn "未安装 jq 或 python3，跳过 JSON 格式验证"
        return 0
    else
        print_error "文件不是有效的 JSON 格式"
        return 1
    fi
}

# 生成服务器配置（VLESS + REALITY + gRPC）
generate_server_config() {
    local server_ip=$1
    local server_port=${2:-443}
    local output_file=$3
    local uuid=${4:-""}
    local xray_bin=${5:-"/usr/local/bin/xray"}
    
    # 生成参数
    if [ -z "$uuid" ]; then
        uuid=$(generate_uuid)
    fi
    
    local short_id=$(generate_short_id)
    local sni_target=$(random_sni_target)
    local grpc_service_name=$(random_grpc_service_name)
    
    print_info "生成配置参数:"
    print_info "  UUID: $uuid"
    print_info "  ShortID: $short_id"
    print_info "  SNI 目标: $sni_target"
    print_info "  gRPC ServiceName: $grpc_service_name"
    
    # 生成 REALITY 密钥对
    print_info "生成 REALITY 密钥对..."
    local key_pair=$(generate_reality_keys "$xray_bin")
    if [ $? -ne 0 ]; then
        print_error "无法生成 REALITY 密钥对"
        return 1
    fi
    
    local private_key=$(echo "$key_pair" | cut -d'|' -f1)
    local public_key=$(echo "$key_pair" | cut -d'|' -f2)
    
    print_success "REALITY 密钥对已生成"
    print_info "  Private Key: $private_key"
    print_info "  Public Key: $public_key"
    
    # 生成服务器配置文件（符合 Xray-core 最新规范）
    cat > "$output_file" << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "port": ${server_port},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "flow": ""
                    }
                ],
                "decryption": "none",
                "fallbacks": []
            },
            "streamSettings": {
                "network": "grpc",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "${sni_target}:443",
                    "xver": 0,
                    "serverNames": [
                        "${sni_target}"
                    ],
                    "privateKey": "${private_key}",
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [
                        "${short_id}"
                    ]
                },
                "grpcSettings": {
                    "serviceName": "${grpc_service_name}",
                    "multiMode": false
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ],
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true
        }
    },
    "stats": {},
    "api": {
        "tag": "api",
        "services": [
            "StatsService"
        ]
    }
}
EOF

    # 验证生成的 JSON
    if ! validate_json "$output_file"; then
        print_error "生成的配置文件格式错误"
        return 1
    fi
    
    # 保存连接信息
    local info_file="${output_file%.json}.info"
    cat > "$info_file" << EOF
# Xray VLESS + REALITY + gRPC 连接信息
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

服务器配置:
  地址: ${server_ip}
  端口: ${server_port}
  协议: VLESS + REALITY + gRPC

客户端连接参数:
  UUID: ${uuid}
  ShortID: ${short_id}
  Public Key: ${public_key}
  Server Name: ${sni_target}
  gRPC ServiceName: ${grpc_service_name}
EOF

    print_success "服务器配置文件已生成: $output_file"
    print_info "连接信息已保存: $info_file"
    
    # 返回连接信息（用于生成客户端配置）
    echo "${uuid}|${short_id}|${public_key}|${sni_target}|${grpc_service_name}"
    return 0
}

# 生成客户端配置（JSON 格式）
generate_client_config() {
    local server_ip=$1
    local server_port=$2
    local uuid=$3
    local public_key=$4
    local server_name=$5
    local short_id=$6
    local grpc_service_name=$7
    
    cat << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 10808,
            "protocol": "socks",
            "settings": {
                "udp": true
            }
        },
        {
            "port": 10809,
            "protocol": "http"
        }
    ],
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "${server_ip}",
                        "port": ${server_port},
                        "users": [
                            {
                                "id": "${uuid}",
                                "encryption": "none",
                                "flow": ""
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "fingerprint": "chrome",
                    "serverName": "${server_name}",
                    "publicKey": "${public_key}",
                    "shortId": "${short_id}",
                    "spiderX": "/"
                },
                "grpcSettings": {
                    "serviceName": "${grpc_service_name}",
                    "multiMode": false
                }
            }
        }
    ]
}
EOF
}

# 生成客户端配置链接（v2rayN/v2rayNG 格式）
generate_client_link() {
    local server_ip=$1
    local server_port=$2
    local uuid=$3
    local public_key=$4
    local server_name=$5
    local short_id=$6
    local grpc_service_name=$7
    
    # Base64 编码配置
    local config_json=$(cat << EOF | tr -d '\n' | tr -d ' '
{
    "v": "2",
    "ps": "Xray-REALITY-gRPC",
    "add": "${server_ip}",
    "port": "${server_port}",
    "id": "${uuid}",
    "aid": "0",
    "scy": "none",
    "net": "grpc",
    "type": "none",
    "host": "${server_name}",
    "path": "${grpc_service_name}",
    "tls": "reality",
    "sni": "${server_name}",
    "alpn": "",
    "fp": "chrome",
    "pbk": "${public_key}",
    "sid": "${short_id}",
    "spx": "/"
}
EOF
)
    
    local encoded=$(echo -n "$config_json" | base64 -w 0 2>/dev/null || echo -n "$config_json" | base64 | tr -d '\n')
    echo "vless://${uuid}@${server_ip}:${server_port}?type=grpc&security=reality&sni=${server_name}&pbk=${public_key}&sid=${short_id}&spx=%2F&serviceName=${grpc_service_name}&fp=chrome#Xray-REALITY-gRPC"
}

# 主函数：生成配置并输出客户端信息
generate_vless_reality_grpc_config() {
    local server_ip=$1
    local server_port=${2:-443}
    local output_file=$3
    local uuid=${4:-""}
    local xray_bin=${5:-"/usr/local/bin/xray"}
    
    print_info "=========================================="
    print_info "生成 VLESS + REALITY + gRPC 配置"
    print_info "=========================================="
    
    # 生成服务器配置
    local config_info=$(generate_server_config "$server_ip" "$server_port" "$output_file" "$uuid" "$xray_bin")
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 解析配置信息
    local uuid_val=$(echo "$config_info" | cut -d'|' -f1)
    local short_id=$(echo "$config_info" | cut -d'|' -f2)
    local public_key=$(echo "$config_info" | cut -d'|' -f3)
    local server_name=$(echo "$config_info" | cut -d'|' -f4)
    local grpc_service_name=$(echo "$config_info" | cut -d'|' -f5)
    
    # 输出客户端配置信息
    echo ""
    print_info "=========================================="
    print_info "客户端配置信息"
    print_info "=========================================="
    echo ""
    
    print_info "连接参数:"
    echo "  服务器地址: ${server_ip}"
    echo "  端口: ${server_port}"
    echo "  UUID: ${uuid_val}"
    echo "  Public Key: ${public_key}"
    echo "  ShortID: ${short_id}"
    echo "  Server Name: ${server_name}"
    echo "  gRPC ServiceName: ${grpc_service_name}"
    echo ""
    
    print_info "客户端 JSON 配置:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    generate_client_config "$server_ip" "$server_port" "$uuid_val" "$public_key" \
        "$server_name" "$short_id" "$grpc_service_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    print_info "客户端导入链接 (v2rayN/v2rayNG):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    generate_client_link "$server_ip" "$server_port" "$uuid_val" "$public_key" \
        "$server_name" "$short_id" "$grpc_service_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    print_success "配置生成完成！"
    return 0
}

# 远程生成配置（在远程服务器上执行）
generate_config_remote() {
    local server_ip=$1
    local server_port=$2
    local ssh_user=$3
    local ssh_key=$4
    local server_port_config=${5:-443}
    local xray_bin=${6:-"/usr/local/bin/xray"}
    
    # 这个函数需要在远程服务器上执行
    # 通过 SSH 调用远程的配置生成
    local ssh_cmd="ssh -p $server_port -o StrictHostKeyChecking=no"
    if [ -n "$ssh_key" ]; then
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        if [ -f "$ssh_key" ]; then
            ssh_cmd="$ssh_cmd -i $ssh_key"
        fi
    fi
    ssh_cmd="$ssh_cmd $ssh_user@$server_ip"
    
    # 在远程执行配置生成
    local remote_script="
        source /tmp/xray_ops/config_generator.sh
        generate_vless_reality_grpc_config '$server_ip' '$server_port_config' '/tmp/xray_config.json' '' '$xray_bin'
        if [ \$? -eq 0 ]; then
            mkdir -p /usr/local/etc/xray
            mv /tmp/xray_config.json /usr/local/etc/xray/config.json
            chmod 644 /usr/local/etc/xray/config.json
            echo 'SUCCESS'
        else
            echo 'FAILED'
        fi
    "
    
    $ssh_cmd "bash -c '$remote_script'"
}

# 兼容旧接口
generate_vless_reality_config() {
    # 调用新的函数，但使用 TCP 而不是 gRPC（向后兼容）
    generate_vless_reality_grpc_config "$@"
}

# 如果脚本被直接执行（而非被 source），运行配置生成
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    if [ $# -lt 2 ]; then
        echo "用法: $0 <server_ip> <output_file> [port] [uuid]"
        exit 1
    fi
    generate_vless_reality_grpc_config "$1" "${3:-443}" "$2" "${4:-}"
fi
