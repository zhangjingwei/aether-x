# Aether-X

**版本：0.9.1**

在多台 Linux VPS 上批量部署 **Xray-core**（**VLESS + WebSocket + TLS**，服务端自签名证书），支持健康检查与订阅生成（与 **Clash** 等客户端 URI 格式兼容）。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Protocol](https://img.shields.io/badge/Protocol-VLESS%20%7C%20WS%20%7C%20TLS-blue.svg)](https://github.com/XTLS/Xray-core)

## 快速开始

```bash
git clone https://github.com/zhangjingwei/aether-x.git
cd aether-x
cp configs/servers.yaml.example configs/servers.yaml
# 编辑 configs/servers.yaml，填写 IP、SSH 用户与密钥路径
./main.sh
```

主菜单：`[1]` 批量部署 · `[2]` 节点状态 · `[3]` 健康检查 · `[4]` 生成订阅 · `[5]` 卸载 · `[0]` 退出。

查看版本：`./main.sh --version`（版本号以仓库根目录 `VERSION` 文件为准）。

## 功能概要

- SSH 批量安装 Xray、生成配置（UUID、随机 WS 路径、`/etc/ssl` 下自签名证书）
- 系统调优（BBR、TCP、Swap、Xray 的 systemd 资源限制等，由 `modules/sys_tuner.sh` 执行）
- TCP / ICMP / TLS 健康检查；订阅仅包含健康节点，输出在 `dist/`
- 可选：将订阅分发到 S3、GitHub Pages 或 VPS（见 `modules/sub_manager.sh`）

## 目录结构（摘要）

| 路径 | 说明 |
|------|------|
| `main.sh` | 入口 |
| `modules/` | 部署、配置生成、健康检查、订阅等脚本 |
| `configs/servers.yaml` | 节点列表（需自行配置） |
| `templates/vless-ws.json` | 配置参考模板 |
| `dist/` | 生成的订阅文件 |
| `logs/` | 健康检查日志 |

## 配置示例

```yaml
servers:
  - alias: my-node
    ip: 203.0.113.10
    ssh_port: 22
    ssh_user: root
    ssh_key: ~/.ssh/id_ed25519
```

更多字段可参考 `configs/servers.yaml.example`。

## 依赖

**控制端**：`bash`、`ssh`/`scp`、`curl` 或 `wget`；生成订阅解析 YAML 建议安装 [`yq`](https://github.com/mikefarah/yq)。

**节点**：由脚本安装 Xray；写证书与配置需要 root（通过 SSH 与 `sudo` 执行）。

## 环境变量（常用）

| 变量 | 说明 |
|------|------|
| `CONFIG_FILE` | 自定义 `servers.yaml` 路径 |
| `SKIP_TUNING` | 设为 `true` 可跳过系统调优 |
| `MAX_PARALLEL` | 并发上限（默认 `10`） |
| `DEBUG` | 设为 `true` 输出调试信息 |

## 安全提示

- 勿将 `configs/*.info`（含 UUID、路径等）提交到 Git。
- 自签名 TLS 的订阅链接含 `allowInsecure=1`，请妥善保管订阅地址。

## 故障排查（简要）

1. 部署失败：检查安全组与本机 `ssh -vvv` 能否登录；密钥权限 `chmod 600`。
2. Xray 起不来：在节点上执行 `journalctl -u xray -n 50` 与 `xray -test -config /usr/local/etc/xray/config.json`。
3. 订阅为空：先跑健康检查；查看 `logs/last_check.log` 与 `dist/*.raw.txt`。

## 卸载

菜单选 `[5]`，或在节点上停止服务后删除 `/usr/local/bin/xray`、`/usr/local/etc/xray`、`/var/log/xray` 与 `xray` 的 systemd 单元（详见 `modules/uninstaller.sh`）。

## 许可证

MIT License

## 致谢

[Xray-core](https://github.com/XTLS/Xray-core)

---

**免责声明**：本软件按「原样」提供，仅供学习与研究网络自动化部署使用。使用者须自行遵守所在地法律法规及服务条款，开发者不对任何滥用或后果承担责任。
