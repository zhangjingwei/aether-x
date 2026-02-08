# Aether-X

下一代 Xray-core 自动化部署与多节点管理平台  
支持实时健康监测、故障自愈、内核级优化的企业级代理解决方案

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)
[![Architecture](https://img.shields.io/badge/Arch-x86__64%20%7C%20ARM64-green.svg)](https://en.wikipedia.org/wiki/X86-64)
[![Protocol](https://img.shields.io/badge/Protocol-REALITY%20%7C%20gRPC-orange.svg)](https://github.com/XTLS/REALITY)
[![OS Support](https://img.shields.io/badge/OS-Ubuntu%20%7C%20Debian%20%7C%20CentOS-lightgrey.svg)](https://www.ubuntu.com/)

## 快速开始

只需三行代码，即可开始使用：

```bash
git clone https://github.com/zhangjingwei/aether-x.git
cd aether-x
./main.sh
```

编辑 `configs/servers.yaml` 添加你的服务器配置，然后运行 `./main.sh` 选择批量部署。

## 为什么选择 Aether-X?

| 特性维度 | 传统一键脚本 | **Aether-X** |
|---------|------------|-------------|
| **多机编排** | 单机部署，需手动重复操作 | **Multi-Region Infrastructure Orchestration**<br/>支持跨云、跨区域的统一编排管理 |
| **故障自愈** | 无健康监测，需人工排查 | **Real-time Health Self-healing**<br/>三维检测体系 + 自动故障隔离 + 智能订阅更新 |
| **资源隔离** | 无资源限制，可能影响系统稳定性 | **Cgroups-based Resource Isolation**<br/>内存/CPU 硬限制，防止资源耗尽攻击 |
| **配置管理** | 手动配置，易出错 | **Automated Configuration Generation**<br/>自动生成 UUID、密钥对、ShortID |
| **订阅分发** | 手动维护订阅链接 | **Intelligent Subscription Management**<br/>基于健康状态的动态订阅生成 |
| **系统优化** | 基础优化 | **Kernel-level Performance Tuning**<br/>BBR + TCP 参数优化 + Swap 管理 |

## 系统架构

Aether-X 采用 Controller-Node 架构模式，通过 SSH 协议实现集中式管理：

- **控制端（Control Plane）**：运行 `main.sh` 的本地/管理服务器，负责读取配置、连接远程节点、执行部署和监控
- **节点（Data Plane）**：远程 VPS 服务器，运行 Xray-core 服务，支持 x86_64 和 ARM64 架构
- **安全通道**：SSH（端口可配置）+ 密钥认证
- **健康监测**：三维检测体系（TCP/ICMP/应用层）+ 实时故障自愈
- **订阅分发**：智能订阅生成（仅包含健康节点），支持 S3/GitHub Pages/VPS 分发

## 核心特性

### 实时健康监测与故障自愈

- **三维检测体系**：
  - **TCP 层**：端口连通性检测（443/自定义端口）
  - **ICMP 层**：延迟与丢包率监控
  - **应用层**：TLS 握手验证
- **自动故障隔离**：失败节点自动从订阅中剔除
- **智能订阅更新**：仅包含健康节点，确保用户连接质量

### 内核级优化

- **BBR 拥塞控制**：自动检测内核版本并启用 BBR
- **TCP 参数调优**：
  - 缓冲区优化（`net.core.rmem_max`, `net.core.wmem_max`）
  - 连接跟踪表扩展（`net.netfilter.nf_conntrack_max`）
  - 文件描述符限制（`ulimit -n 1048576`）
- **系统资源限制**：通过 Cgroups 硬限制 Xray 服务资源
  - 内存限制：200MB
  - CPU 限制：50%
- **Swap 智能管理**：内存 < 2GB 时自动创建 Swap

### 隐私与安全

- **REALITY 协议**：无指纹 TLS 流量伪装
  - 自动生成 X25519 密钥对
  - 随机选择 SNI 目标（如 `www.microsoft.com`）
  - 支持 gRPC 传输，降低流量特征
- **Cgroups 资源硬限制**：防止资源耗尽攻击
  - 内存硬限制（OOM Killer 保护）
  - CPU 配额限制（防止 CPU 100%）
- **SSH 密钥认证**：禁用密码登录，仅支持密钥
- **配置文件加密存储**：敏感信息（UUID、密钥）单独存储

### 其他核心功能

- **自动配置生成** - VLESS + REALITY + gRPC，自动生成 UUID、密钥对、ShortID
- **多区域基础设施编排** - 通过 SSH 批量部署到多台服务器，支持并发部署
- **环境自动检测** - 识别系统架构、发行版、云服务商，提供防火墙配置建议
- **订阅链接管理** - 自动生成 Base64 编码的订阅文件，支持 S3/GitHub Pages/VPS 分发
- **交互式菜单** - 友好的命令行界面，支持批量部署、状态检查

## 项目结构

```
aether-x/
├── main.sh                    # 主入口脚本
│
├── modules/                    # 功能模块
│   ├── xray_manager.sh        # Xray 二进制管理（下载/安装/架构检测）
│   ├── config_generator.sh    # 配置生成器
│   ├── multi_server.sh        # 多机管理（SSH 部署）
│   ├── health_checker.sh      # 健康检查模块
│   ├── sub_manager.sh         # 订阅管理模块
│   ├── service_manager.sh     # 服务管理（systemd）
│   ├── sys_tuner.sh           # 系统优化器（BBR/内核参数/Swap/Cgroups）
│   └── uninstaller.sh         # 卸载模块
│
├── templates/                  # 配置模板
│   ├── vless-reality.json     # VLESS + REALITY 模板
│   └── vless-ws.json          # VLESS + WebSocket 模板
│
├── configs/                    # 配置文件
│   ├── servers.yaml           # 服务器列表（用户配置）
│   ├── servers.yaml.example   # 配置示例
│   └── *.info                 # 节点配置信息（从服务端自动拉取，包含UUID、PublicKey等）
│
├── dist/                       # 输出目录
│   ├── sub_*.txt             # 生成的订阅文件（Base64编码）
│   └── sub_*.raw.txt          # 原始订阅URL列表（未编码）
│
└── logs/                       # 日志目录
    ├── check_YYYYMMDD_HHMMSS.log  # 健康检查日志（按时间戳保存）
    └── last_check.log         # 最新日志的符号链接
```

## 使用指南

### 交互式菜单（推荐）

运行 `./main.sh` 后，你将看到以下交互式菜单：

```
========================================
Aether-X 运维工具主菜单
========================================

请选择操作:

  [1] 批量部署远程节点
  [2] 检查所有节点在线状态
  [3] 健康检查（TCP/ICMP/应用层检测）
  [4] 生成订阅链接
  [5] 批量卸载远程节点
  [0] 退出

请输入选项 [0-5]: 
```

菜单选项说明：
- `[1]` 批量部署远程节点 - 选择服务器进行部署
- `[2]` 检查所有节点在线状态 - 快速状态检查
- `[3]` 健康检查（TCP/ICMP/应用层检测） - 三维检测体系
- `[4]` 生成订阅链接 - 基于健康检查结果生成订阅
- `[5]` 批量卸载远程节点 - 选择服务器进行卸载

### 环境变量配置

Aether-X 支持通过环境变量自定义行为。在运行脚本前设置以下变量：

| 环境变量 | 默认值 | 说明 | 示例 |
|---------|--------|------|------|
| `CONFIG_FILE` | `configs/servers.yaml` | 指定服务器配置文件路径 | `export CONFIG_FILE=/path/to/servers.yaml` |
| `SKIP_TUNING` | `false` | 跳过系统优化（仅部署 Xray） | `export SKIP_TUNING=true` |
| `SKIP_HEALTH_CHECK` | `false` | 跳过健康检查（直接生成订阅） | `export SKIP_HEALTH_CHECK=true` |
| `MAX_PARALLEL` | `10` | 最大并发部署/检查数 | `export MAX_PARALLEL=5` |
| `XRAY_VERSION` | `latest` | 指定 Xray 版本 | `export XRAY_VERSION=1.8.4` |
| `LOG_LEVEL` | `info` | 日志级别（debug/info/warn/error） | `export LOG_LEVEL=debug` |
| `DEBUG` | `false` | 启用调试输出（显示详细的执行日志） | `export DEBUG=true` |

使用示例：

```bash
# 跳过系统优化，仅部署 Xray
export SKIP_TUNING=true
./main.sh
# 然后在菜单中选择 [1] 批量部署远程节点

# 限制并发数为 5
export MAX_PARALLEL=5
./main.sh
# 然后在菜单中选择 [3] 健康检查

# 使用自定义配置文件
export CONFIG_FILE=/path/to/my-servers.yaml
./main.sh
```


## 配置示例

### servers.yaml

```yaml
servers:
  - alias: aws-us-east-1
    ip: 54.123.45.67
    ssh_port: 22
    ssh_user: root
    ssh_key: ~/.ssh/aws_key.pem
    cloud_provider: aws
    region: us-east-1
    description: "AWS 美国东部服务器"
    tags:
      - production
      - us-region

  - alias: tencent-shanghai
    ip: 119.28.123.45
    ssh_port: 22
    ssh_user: root
    ssh_key: ~/.ssh/tencent_key
    cloud_provider: tencent
    region: ap-shanghai
    description: "腾讯云上海服务器"
    tags:
      - production
      - cn-region
```

## 工作流程

### 批量部署流程

1. **读取配置** - 解析 `configs/servers.yaml`
2. **生成配置** - 为每台服务器自动生成 VLESS + REALITY 配置
   - 生成 UUID
   - 生成 REALITY 密钥对（PrivateKey/PublicKey）
   - 生成 ShortID
   - 随机选择 SNI 目标
3. **远程部署** - 对每台服务器执行（通过 SSH）：
   - 测试 SSH 连接
   - 上传并执行系统优化脚本
   - 安装 Xray-core 二进制
   - 创建配置目录和日志目录
   - 在服务端生成配置文件（`/usr/local/etc/xray/config.json`）
   - 在服务端生成配置信息文件（`/usr/local/etc/xray/config.info`，包含UUID、PublicKey等）
   - 创建 systemd 服务
   - 启动并验证服务
4. **显示统计** - 输出部署结果和状态

**注意**：部署时会在服务端生成 `config.info` 文件，生成订阅时会自动从服务端拉取到本地 `configs/{alias}.info`，方便后续使用。

### 健康检查流程

1. **并发检测** - 同时检测所有节点（默认最大并发数：10）
2. **三维检测**：
   - TCP 端口连通性
   - ICMP 延迟和丢包率
   - TLS 应用层握手
3. **结果缓存** - 按时间戳保存到 `logs/check_YYYYMMDD_HHMMSS.log`，并创建 `last_check.log` 符号链接
4. **自动过滤** - 订阅生成时仅包含健康节点

### 订阅生成流程

1. **读取健康检查日志** - 从最新的健康检查日志提取 OK 状态节点（支持选择历史日志）
2. **获取节点配置** - 按以下优先级获取配置信息：
   - **方法1**：从本地 `configs/*.info` 文件读取（如果存在）
   - **方法2**：从服务端拉取 info 文件到本地（`/usr/local/etc/xray/config.info` → `configs/{alias}.info`）
   - **方法3**：从远程服务器读取配置文件并解析（备用方案）
3. **生成 VLESS URL** - 格式：`vless://uuid@ip:port?type=grpc&security=reality&...`
4. **Base64 编码** - 将所有 URL 编码为订阅格式
5. **文件随机化** - 生成随机文件名（如 `sub_aad85773.txt`），同时保存原始 URL 文件（`.raw.txt`）
6. **可选分发** - 上传到 S3/GitHub Pages/VPS

## 系统优化详情

自动应用以下优化（通过 `sys_tuner.sh`）：

### 内核参数优化

- **BBR 拥塞控制** - 自动检测内核版本并启用
- **TCP 缓冲区**：
  ```bash
  net.core.rmem_max = 134217728
  net.core.wmem_max = 134217728
  net.ipv4.tcp_rmem = 4096 87380 134217728
  net.ipv4.tcp_wmem = 4096 65536 134217728
  ```
- **连接跟踪表**：`net.netfilter.nf_conntrack_max = 1048576`
- **文件描述符**：`ulimit -n 1048576`

### 资源限制（Cgroups）

通过 systemd 服务配置：

```ini
[Service]
MemoryLimit=200M
CPUQuota=50%
```

- **内存硬限制**：200MB（超出即被 OOM Killer 终止）
- **CPU 配额**：50%（防止 CPU 100%）

### Swap 管理

- 自动检测内存大小
- 内存 < 2GB 时自动创建 Swap（大小为内存的 2 倍）

## 环境检测

自动检测以下信息（通过 `xray_manager.sh` 和部署流程）：

- **系统架构** - 自动检测 x86_64/ARM64 架构（通过 `detect_arch()` 函数）
- **系统信息** - 发行版、内核版本（在部署过程中自动检测）
- **防火墙状态** - 部署时提供防火墙配置建议

## 依赖要求

### 必需工具

- `bash` (4.0+)
- `curl`, `openssl`, `systemctl`
- `ssh` / `scp`
- `wget` 或 `curl`（用于下载）
- `unzip`（用于解压）

### 推荐工具

- `yq` - YAML 解析（推荐安装）
  ```bash
  wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq
  chmod +x /usr/local/bin/yq
  ```

## 使用示例

### 示例 1: 快速部署

```bash
# 1. 克隆项目
git clone https://github.com/zhangjingwei/aether-x.git
cd aether-x

# 2. 编辑服务器配置
vim configs/servers.yaml

# 3. 运行部署
./main.sh
# 选择 [2] 批量部署远程节点
```

### 示例 2: 健康检查与订阅生成

```bash
# 1. 运行主程序
./main.sh

# 2. 选择 [3] 执行健康检查（TCP/ICMP/应用层检测）

# 3. 选择 [4] 生成订阅链接（仅包含健康节点）

# 4. 订阅文件保存在 dist/sub_*.txt
```

### 示例 3: 查看节点状态

```bash
# 运行主程序
./main.sh

# 选择 [2] 检查所有节点在线状态
```

输出示例：
```
[SUCCESS] 服务器 aws-us-east-1 (54.123.45.67): Xray 服务运行中 - Xray 1.8.4
[SUCCESS] 服务器 tencent-shanghai (119.28.123.45): Xray 服务运行中 - Xray 1.8.4
[WARN] 服务器 gcp-asia-east (35.201.123.45): Xray 服务未运行

状态统计
[SUCCESS] 在线: 2 台
[WARN] 离线: 1 台
```

## 安全注意事项

1. **SSH 密钥** - 确保密钥文件权限为 600，使用密钥认证而非密码
2. **配置文件** - `.info` 文件包含敏感信息（UUID、密钥），不要提交到版本控制
3. **防火墙** - 部署前配置安全组/防火墙规则，参考环境检测器的建议
4. **订阅文件** - 订阅链接包含节点信息，请妥善保管，避免泄露
5. **REALITY 协议** - 使用无指纹 TLS 伪装，降低流量特征识别风险

## 故障排查

Aether-X 采用分层排查策略，从底层网络到上层应用逐层诊断问题。

### 网络层排查

#### SSH 连接失败

**症状**：部署时无法连接到远程服务器

```bash
# 1. 检查网络连通性（ICMP）
ping -c 4 <server_ip>

# 2. 检查 SSH 端口是否开放
nc -zv <server_ip> <ssh_port>
# 或使用 telnet
telnet <server_ip> <ssh_port>

# 3. 测试 SSH 连接（详细模式）
ssh -vvv -i ~/.ssh/key.pem -p <ssh_port> root@<server_ip>

# 4. 检查密钥权限（必须是 600）
ls -l ~/.ssh/key.pem
chmod 600 ~/.ssh/key.pem

# 5. 检查 SSH 配置
cat ~/.ssh/config
```

**常见问题**：
- 防火墙阻止 SSH 端口 → 检查云服务商安全组规则
- 密钥权限错误 → `chmod 600 ~/.ssh/key.pem`
- SSH 服务未运行 → 在目标服务器执行 `systemctl status sshd`

#### TCP 端口连通性

**症状**：健康检查显示 TCP 连接失败

```bash
# 1. 从本地测试端口
nc -zv <server_ip> 443
# 或使用 telnet
telnet <server_ip> 443

# 2. 从远程服务器测试（如果 SSH 可用）
ssh root@<server_ip> "nc -zv localhost 443"

# 3. 检查防火墙规则
# Ubuntu/Debian
sudo ufw status
sudo iptables -L -n

# CentOS/RHEL
sudo firewall-cmd --list-all
sudo iptables -L -n

# 4. 检查端口监听状态
ssh root@<server_ip> "ss -tlnp | grep 443"
# 或
ssh root@<server_ip> "netstat -tlnp | grep 443"
```

### 协议层排查

#### Xray 服务启动失败

**症状**：服务无法启动或频繁重启

```bash
# 1. 查看 systemd 服务状态
systemctl status xray
# 或远程查看
ssh root@<server_ip> "systemctl status xray"

# 2. 查看实时日志（最后 50 行）
journalctl -u xray -n 50 --no-pager
# 或远程查看
ssh root@<server_ip> "journalctl -u xray -n 50 --no-pager"

# 3. 查看完整日志（实时跟踪）
journalctl -u xray -f
# 或查看所有日志
journalctl -u xray --no-pager

# 4. 检查配置文件语法
/usr/local/bin/xray -test -config /usr/local/etc/xray/config.json
# 或远程检查
ssh root@<server_ip> "/usr/local/bin/xray -test -config /usr/local/etc/xray/config.json"

# 5. 检查 Xray 二进制文件
/usr/local/bin/xray version
# 或远程检查
ssh root@<server_ip> "/usr/local/bin/xray version"

# 6. 检查端口占用
ss -tlnp | grep 443
# 或
lsof -i :443
```

**常见错误及解决方案**：

| 错误信息 | 可能原因 | 解决方案 |
|---------|---------|---------|
| `bind: address already in use` | 端口被占用 | `ss -tlnp \| grep 443` 查找占用进程并终止 |
| `invalid config` | 配置文件格式错误 | `xray -test -config config.json` 检查语法 |
| `permission denied` | 权限不足 | 检查文件权限，确保 xray 可读配置 |
| `failed to start` | 资源限制 | 检查 Cgroups 限制，查看 `systemctl status xray` |

#### 应用层连接问题

**症状**：TCP 连接成功但应用层握手失败

```bash
# 1. 测试 TLS 握手
openssl s_client -connect <server_ip>:443 -servername <server_ip>

# 2. 检查证书（如果使用 TLS）
openssl s_client -connect <server_ip>:443 -showcerts

# 3. 查看 Xray 访问日志
tail -f /var/log/xray/access.log
# 或远程查看
ssh root@<server_ip> "tail -f /var/log/xray/access.log"

# 4. 查看 Xray 错误日志
tail -f /var/log/xray/error.log
# 或远程查看
ssh root@<server_ip> "tail -f /var/log/xray/error.log"
```

### 分发层排查

#### YAML 配置解析失败

**症状**：无法读取 `servers.yaml` 或解析错误

```bash
# 1. 验证 YAML 语法
yq eval '.servers[]' configs/servers.yaml

# 2. 检查 YAML 格式（使用在线工具或 yamllint）
yamllint configs/servers.yaml

# 3. 查看服务器列表
yq eval '.servers[].alias' configs/servers.yaml

# 4. 检查特定服务器配置
yq eval '.servers[] | select(.alias == "server-1")' configs/servers.yaml

# 5. 如果没有 yq，安装它
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq
chmod +x /usr/local/bin/yq
```

**常见 YAML 错误**：
- 缩进错误（必须使用空格，不能使用 Tab）
- 缺少冒号或引号
- 数组格式错误

#### 订阅生成失败

**症状**：无法生成订阅或订阅为空

```bash
# 1. 查看最新的健康检查日志
cat logs/last_check.log

# 2. 查看所有历史日志
ls -lh logs/check_*.log

# 3. 查看健康节点列表
grep "整体状态: OK" logs/last_check.log

# 3. 检查订阅文件
ls -lh dist/sub_*.txt
cat dist/sub_*.raw.txt  # 查看原始 URL 列表

# 4. 验证 Base64 编码
base64 -d dist/sub_*.txt

# 5. 检查节点配置信息
# 从本地 info 文件（如果已拉取）
cat configs/*.info

# 从远程服务器 info 文件
ssh root@<server_ip> "cat /usr/local/etc/xray/config.info"

# 从远程服务器配置文件
ssh root@<server_ip> "cat /usr/local/etc/xray/config.json | jq '.inbounds[0]'"
```

#### 订阅分发失败

**症状**：订阅文件生成成功但无法上传到分发服务器

```bash
# S3 分发失败
# 1. 检查 AWS CLI 配置
aws configure list

# 2. 测试 S3 连接
aws s3 ls s3://<bucket-name>

# 3. 检查权限
aws s3api get-bucket-acl --bucket <bucket-name>

# GitHub Pages 分发失败
# 1. 验证 Token 权限
curl -H "Authorization: token <token>" https://api.github.com/user

# 2. 检查仓库权限
curl -H "Authorization: token <token>" https://api.github.com/repos/<owner>/<repo>

# VPS 分发失败
# 1. 测试 SSH 连接
ssh -i <key> <user>@<vps_ip>

# 2. 检查目录权限
ssh <user>@<vps_ip> "ls -ld <remote_path>"

# 3. 检查 Nginx 配置（如果使用 HTTP 访问）
ssh <user>@<vps_ip> "nginx -t"
```

### 综合排查流程

当遇到问题时，按以下顺序排查：

```bash
# Step 1: 网络层 - 检查基础连通性
ping <server_ip>
nc -zv <server_ip> <ssh_port>

# Step 2: SSH 层 - 验证远程访问
ssh -i ~/.ssh/key.pem root@<server_ip> "echo 'SSH OK'"

# Step 3: 服务层 - 检查 Xray 服务状态
ssh root@<server_ip> "systemctl status xray"

# Step 4: 协议层 - 查看服务日志
ssh root@<server_ip> "journalctl -u xray -n 50"

# Step 5: 应用层 - 测试端口和协议
nc -zv <server_ip> 443
openssl s_client -connect <server_ip>:443

# Step 6: 配置层 - 验证配置文件
yq eval '.servers[]' configs/servers.yaml
ssh root@<server_ip> "/usr/local/bin/xray -test -config /usr/local/etc/xray/config.json"
```

### 日志文件位置

| 日志类型 | 路径 | 查看命令 |
|---------|------|---------|
| Xray 服务日志 | systemd journal | `journalctl -u xray -f` |
| Xray 访问日志 | `/var/log/xray/access.log` | `tail -f /var/log/xray/access.log` |
| Xray 错误日志 | `/var/log/xray/error.log` | `tail -f /var/log/xray/error.log` |
| 健康检查日志 | `logs/check_*.log` | `cat logs/last_check.log` 或 `ls logs/check_*.log` |
| 部署结果日志 | 临时文件 | 查看 `multi_server.sh` 输出 |

## 卸载

### 通过菜单卸载

```bash
./main.sh
# 选择 [5] 批量卸载远程节点
```

### 手动卸载

```bash
systemctl stop xray
systemctl disable xray
rm -f /usr/local/bin/xray
rm -rf /usr/local/etc/xray
rm -rf /var/log/xray
rm -f /etc/systemd/system/xray.service
systemctl daemon-reload
```

## 许可证

MIT License

## 致谢

- [Xray-core](https://github.com/XTLS/Xray-core) - 核心代理引擎
- [REALITY](https://github.com/XTLS/REALITY) - 无指纹 TLS 协议

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=zhangjingwei/aether-x&type=Date)](https://star-history.com/#zhangjingwei/aether-x&Date)

## 贡献指南

我们欢迎所有形式的贡献！无论是报告 Bug、提出功能建议，还是提交代码改进，都是对项目的宝贵支持。

### 如何贡献

#### 1. 报告问题（Issues）

如果发现 Bug 或有功能建议，请：

1. 检查 [Issues](https://github.com/zhangjingwei/aether-x/issues) 中是否已有相关问题
2. 如果没有，创建新的 Issue，包含：
   - 清晰的问题描述
   - 复现步骤
   - 预期行为 vs 实际行为
   - 环境信息（OS、架构、版本等）

#### 2. 提交代码（Pull Requests）

1. Fork 本仓库
2. 创建功能分支：`git checkout -b feature/your-feature-name`
3. 提交更改：`git commit -m 'Add some feature'`
4. 推送到分支：`git push origin feature/your-feature-name`
5. 提交 Pull Request

#### 3. 添加新的协议模板

Aether-X 支持扩展新的协议模板。要添加新模板：

1. **创建模板文件**：
   ```bash
   # 在 templates/ 目录下创建新模板
   cp templates/vless-reality.json templates/your-protocol.json
   ```

2. **修改模板**：
   - 使用 `{{VARIABLE}}` 语法定义占位符
   - 参考现有模板的结构

3. **更新配置生成器**：
   - 在 `modules/config_generator.sh` 中添加新协议的生成函数
   - 实现参数提取和 URL 生成逻辑

4. **更新文档**：
   - 在 README.md 中添加新协议的说明
   - 提供配置示例

5. **提交 PR**：
   - 包含模板文件
   - 包含生成器更新
   - 包含测试用例
   - 更新文档

### 贡献指南

- 代码风格：遵循现有代码风格，使用 4 空格缩进
- 提交信息：使用清晰的提交信息，遵循 [Conventional Commits](https://www.conventionalcommits.org/)
- 测试：确保新功能经过充分测试
- 文档：更新相关文档和注释

### 贡献者

感谢所有为 Aether-X 做出贡献的开发者！

<!-- 贡献者列表将由 GitHub Actions 自动生成 -->

## 免责声明

**IMPORTANT LEGAL NOTICE**

This software and its associated documentation (collectively, the "Software") are provided for **academic research and operational testing purposes only**. The Software is intended to be used in controlled environments for:

- Academic research in network protocols, distributed systems, and infrastructure automation
- Operational testing and evaluation of network infrastructure management tools
- Educational purposes related to system administration and DevOps practices

**NO WARRANTY**: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

**LIMITATION OF LIABILITY**: IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**COMPLIANCE**: Users are solely responsible for ensuring that their use of the Software complies with all applicable laws, regulations, and terms of service of any third-party services or platforms they may use in connection with the Software.

**PROHIBITED USES**: The Software shall not be used for any illegal, unauthorized, or unethical purposes. The authors and contributors disclaim all responsibility for any misuse of the Software.

By using this Software, you acknowledge that you have read, understood, and agree to be bound by this disclaimer.

---

**Aether-X** - 让代理部署变得简单、可靠、安全。
