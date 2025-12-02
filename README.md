# Xray 服务器一键安装脚本

## 快速开始

### 安装 Xray 服务器

```bash
sudo bash install-xray.sh
```

### 查看当前 UUID

```bash
sudo bash install-xray.sh -u
```

## 功能特性

- ✅ 自动检测系统架构并下载最新版 Xray
- ✅ 自动创建 VLESS 服务器配置（端口 443，WebSocket + TLS）
- ✅ 自动生成客户端 UUID 和自签名证书
- ✅ 自动创建交换空间（如不存在）
- ✅ 系统性能优化（内核参数、BBR、资源限制等）
- ✅ 创建 systemd 服务并自动启动

## 安装前准备

1. **root 权限**：确保以 root 用户运行
2. **证书**（可选）：
   - 脚本会自动生成自签名证书（10 年有效期）
   - 或手动放置证书到 `/usr/local/etc/xray/cert/`（`certificate.crt` 和 `private.key`）
3. **端口**：确保 443 端口未被占用

## 安装后

安装完成后，脚本会自动显示：
- 📊 服务状态和端口监听情况
- 🔗 客户端连接信息（服务器地址、UUID、端口、路径）
- 📝 常用管理命令
- ⚙️ 系统优化状态

### 常用命令

```bash
# 查看当前 UUID
sudo bash install-xray.sh -u

# 服务管理
sudo systemctl start|stop|restart|status xray

# 查看日志
sudo journalctl -u xray -f
sudo tail -f /var/log/xray/access.log
```

## 重要文件位置

- **配置文件**：`/usr/local/etc/xray/config.json`
- **证书目录**：`/usr/local/etc/xray/cert/`
- **日志目录**：`/var/log/xray/`

## 性能优化

脚本会自动应用以下优化：
- TCP/IP 内核参数优化（立即生效）
- BBR 拥塞控制算法
- 交换空间优化（swappiness=10）
- 系统资源限制提升
- 进程优先级和 I/O 调度优化

## 故障排查

```bash
# 查看错误日志
sudo journalctl -u xray -n 50 --no-pager

# 检查配置文件
sudo /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json

# 检查端口占用
sudo ss -tlnp | grep 443
```

## 卸载

```bash
sudo systemctl stop xray
sudo systemctl disable xray
sudo rm /etc/systemd/system/xray.service
sudo rm -rf /etc/systemd/system/xray.service.d
sudo rm -rf /usr/local/etc/xray
sudo rm -rf /var/log/xray
sudo rm /usr/local/bin/xray
sudo systemctl daemon-reload
```
