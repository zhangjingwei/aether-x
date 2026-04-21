#!/bin/bash

# 配置生成模块
# 生成 VLESS + WebSocket + TLS（自签名证书），与 Clash 等客户端订阅格式一致

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
        openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
    fi
}

# 随机 WebSocket 路径（含前导 /）
random_ws_path() {
    echo "/vless-$(openssl rand -hex 8)"
}

# 写入自签名证书（CN 使用服务器 IP，客户端 SNI 与 allowInsecure 配套）
install_self_signed_tls_for_xray() {
    local server_ip=$1
    local key_path="/etc/ssl/private/xray.key"
    local crt_path="/etc/ssl/certs/xray.crt"

    if [ "$EUID" -ne 0 ]; then
        print_error "写入 TLS 证书到 ${crt_path} 需要 root 权限" >&2
        return 1
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        print_error "未找到 openssl，无法生成自签名证书" >&2
        return 1
    fi

    mkdir -p /etc/ssl/private /etc/ssl/certs
    local old_umask
    old_umask=$(umask)
    umask 077
    if ! openssl req -x509 -newkey rsa:2048 -nodes -keyout "$key_path" -out "$crt_path" \
        -days 3650 -subj "/CN=${server_ip}" >/dev/null 2>&1; then
        umask "$old_umask"
        print_error "openssl 生成证书失败" >&2
        return 1
    fi
    umask "$old_umask"
    chmod 600 "$key_path" 2>/dev/null || true
    chmod 644 "$crt_path" 2>/dev/null || true
    print_success "自签名 TLS 证书已写入: ${crt_path}" >&2
    return 0
}

# 验证 JSON 格式
validate_json() {
    local json_file=$1

    if [ ! -f "$json_file" ]; then
        print_error "文件不存在: $json_file"
        return 1
    fi

    if command -v jq >/dev/null 2>&1; then
        if jq empty "$json_file" >/dev/null 2>&1; then
            return 0
        else
            print_error "JSON 格式验证失败"
            jq . "$json_file" 2>&1 | head -10
            return 1
        fi
    fi

    if command -v python3 >/dev/null 2>&1; then
        if python3 -m json.tool "$json_file" >/dev/null 2>&1; then
            return 0
        else
            print_error "JSON 格式验证失败"
            return 1
        fi
    fi

    if grep -q '{' "$json_file" && grep -q '}' "$json_file"; then
        print_warn "未安装 jq 或 python3，跳过 JSON 格式验证"
        return 0
    else
        print_error "文件不是有效的 JSON 格式"
        return 1
    fi
}

# 生成服务器配置（VLESS + WS + TLS）
# 成功时向 stdout 输出一行：uuid|port|ws_path|tls_sni|1|ws（仅此一行，其余走 stderr）
generate_server_config() {
    local server_ip=$1
    local server_port=${2:-443}
    local output_file=$3
    local uuid=${4:-""}

    if [ -z "$uuid" ]; then
        uuid=$(generate_uuid)
    fi

    local ws_path
    ws_path=$(random_ws_path)
    local tls_sni=$server_ip

    print_info "生成配置参数:" >&2
    print_info "  UUID: $uuid" >&2
    print_info "  WebSocket Path: $ws_path" >&2
    print_info "  TLS SNI (证书 CN): $tls_sni" >&2
    print_info "  监听端口: $server_port" >&2

    if ! install_self_signed_tls_for_xray "$server_ip"; then
        return 1
    fi

    # shellcheck disable=SC2016 # JSON 内 ${} 为字面量，由 heredoc 展开的是 shell 变量
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
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/certs/xray.crt",
                            "keyFile": "/etc/ssl/private/xray.key"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "${ws_path}",
                    "headers": {}
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

    if ! validate_json "$output_file"; then
        print_error "生成的配置文件格式错误" >&2
        return 1
    fi

    local info_file="${output_file%.json}.info"
    cat > "$info_file" << EOF
# Xray VLESS + WebSocket + TLS 连接信息
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

服务器配置:
  地址: ${server_ip}
  端口: ${server_port}
  协议: VLESS + WebSocket + TLS（自签名证书）

客户端连接参数:
  UUID: ${uuid}
  WS Path: ${ws_path}
  TLS SNI (与证书 CN 一致): ${tls_sni}
  allowInsecure: 1（自签名证书必须开启）
EOF

    print_success "服务器配置文件已生成: $output_file" >&2
    print_info "连接信息已保存: $info_file" >&2

    echo "${uuid}|${server_port}|${ws_path}|${tls_sni}|1|ws"
    return 0
}

# 生成客户端配置（JSON 格式）
generate_client_config() {
    local server_ip=$1
    local server_port=$2
    local uuid=$3
    local ws_path=$4
    local tls_sni=$5

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
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "${tls_sni}",
                    "allowInsecure": true
                },
                "wsSettings": {
                    "path": "${ws_path}",
                    "headers": {}
                }
            }
        }
    ]
}
EOF
}

# 生成分享链接（与 Clash / 通用 VLESS URI 兼容）
generate_client_link() {
    local server_ip=$1
    local server_port=$2
    local uuid=$3
    local ws_path=$4
    local tls_sni=$5

    local enc_path=$ws_path
    local enc_sni=$tls_sni
    if command -v python3 >/dev/null 2>&1; then
        enc_path=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ws_path")
        enc_sni=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$tls_sni")
    else
        enc_path=${ws_path//\//%2F}
    fi

    echo "vless://${uuid}@${server_ip}:${server_port}?encryption=none&security=tls&type=ws&path=${enc_path}&host=${enc_sni}&sni=${enc_sni}&allowInsecure=1#Xray-VLESS-WS-TLS"
}

# 主函数：生成配置并输出客户端信息
generate_vless_ws_tls_config() {
    local server_ip=$1
    local server_port=${2:-443}
    local output_file=$3
    local uuid=${4:-""}

    print_info "=========================================="
    print_info "生成 VLESS + WebSocket + TLS 配置"
    print_info "=========================================="

    local config_info
    config_info=$(generate_server_config "$server_ip" "$server_port" "$output_file" "$uuid")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local uuid_val
    uuid_val=$(echo "$config_info" | cut -d'|' -f1)
    local port_val
    port_val=$(echo "$config_info" | cut -d'|' -f2)
    local ws_path
    ws_path=$(echo "$config_info" | cut -d'|' -f3)
    local tls_sni
    tls_sni=$(echo "$config_info" | cut -d'|' -f4)

    echo ""
    print_info "=========================================="
    print_info "客户端配置信息"
    print_info "=========================================="
    echo ""

    print_info "连接参数:"
    echo "  服务器地址: ${server_ip}"
    echo "  端口: ${port_val}"
    echo "  UUID: ${uuid_val}"
    echo "  WS Path: ${ws_path}"
    echo "  TLS SNI: ${tls_sni}"
    echo "  allowInsecure: 1"
    echo ""

    print_info "客户端 JSON 配置:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    generate_client_config "$server_ip" "$port_val" "$uuid_val" "$ws_path" "$tls_sni"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    print_info "客户端导入链接:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    generate_client_link "$server_ip" "$port_val" "$uuid_val" "$ws_path" "$tls_sni"
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

    local ssh_cmd="ssh -p $server_port -o StrictHostKeyChecking=no"
    if [ -n "$ssh_key" ]; then
        ssh_key=$(echo "$ssh_key" | sed "s|^~|$HOME|")
        if [ -f "$ssh_key" ]; then
            ssh_cmd="$ssh_cmd -i $ssh_key"
        fi
    fi
    ssh_cmd="$ssh_cmd $ssh_user@$server_ip"

    local remote_script="
        source /tmp/xray_ops/config_generator.sh
        generate_vless_ws_tls_config '$server_ip' '$server_port_config' '/tmp/xray_config.json' ''
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

# 如果脚本被直接执行（而非被 source），运行配置生成
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    if [ $# -lt 2 ]; then
        echo "用法: $0 <server_ip> <output_file> [port] [uuid]"
        exit 1
    fi
    generate_vless_ws_tls_config "$1" "${3:-443}" "$2" "${4:-}"
fi
