# 🛡️ Linux 安全中心

基于 Flask + Docker 的 Linux 服务器安全监控 Web 面板，实时分析暴力破解行为、审计系统安全配置。

## ✨ 功能

### 📊 仪表盘
- 安全评分（基于SSH/防火墙/失败登录等综合计算）
- 7天攻击统计概览（失败次数/攻击IP数/高危IP数/成功登录数）
- SSH配置安全摘要（通过/警告/不安全计数）
- 防火墙 & Fail2Ban 状态
- 系统资源监控（CPU/内存/磁盘）
- 7天攻击趋势柱状图
- TOP 10 攻击源IP
- 最近攻击事件日志

### 🔥 暴力破解分析
- 分析 `/var/log/auth.log`（兼容 Debian/Ubuntu）和 `/var/log/secure`（RHEL/CentOS）
- 支持 journalctl 兜底读取
- 时间范围筛选（1/3/7/14/30天）
- TOP 50 攻击源IP排行（含尝试用户名、风险等级）
- 被爆破用户名统计（含占比图）
- 无效用户名探测排行
- 最近攻击事件原始日志
- lastb 登录失败记录
- **一键 iptables 封禁IP**

### 🔍 安全审计
- **SSH配置检查**：PermitRootLogin、PasswordAuthentication、端口、MaxAuthTries、PubkeyAuthentication、PermitEmptyPasswords
- **防火墙状态**：iptables / nftables / ufw / firewalld
- **Fail2Ban**：运行状态、Jail列表
- **监听端口扫描**：协议/地址/端口/进程/暴露范围/危险端口标记（MySQL/Redis/MongoDB等）
- **用户权限审计**：UID=0用户、可登录用户、sudo组成员、空密码检查
- **SUID/SGID扫描**：全盘扫描非标准SUID文件（白名单过滤）
- **系统更新检查**：apt可升级包列表
- **系统信息**：主机名/OS/内核/架构/运行时间/CPU/内存/磁盘

### 🔐 认证与安全
- **用户名密码登录**：PBKDF2-SHA256 哈希存储，Docker volume 持久化
- **2FA二步验证**：TOTP 协议，支持 Google/Microsoft Authenticator、Authy
- **会话管理**：Flask session，所有页面登录保护
- **明暗主题切换**：深色/浅色双主题，localStorage 持久化
- 修改密码、启用/关闭 2FA 均在 Web 设置页完成

### 📡 API
- `GET /api/brute-force?days=7` — 暴力破解数据JSON
- `GET /api/security-audit` — 安全审计数据JSON
- `POST /api/block-ip` — iptables封禁IP

🔗 **GitHub**: [github.com/yyzq-cf/linux-security-center](https://github.com/yyzq-cf/linux-security-center)

## 🚀 部署

```bash
# 克隆项目
git clone https://github.com/yyzq-cf/linux-security-center.git
cd linux-security-center

# 构建并启动
docker compose up -d --build

# 访问
# http://localhost:8888
```

首次登录使用环境变量配置的默认账号密码，登录后请立即在设置页修改。

### 自定义管理员账号

```yaml
# docker-compose.yml
environment:
  - ADMIN_USER=your_username
  - ADMIN_PASSWORD=your_secure_password
```

## ⚙️ 设计说明

- 使用 `host` 网络模式 + `cap_add` 确保容器能读取宿主机日志、执行iptables/ss/find等命令
- 挂载 `/var/log`、`/etc/ssh`、`/etc/shadow` 等为只读
- 深色/浅色双主题界面，无外部CSS/JS依赖，全部内联
- 实时分析，无数据库依赖
- 认证配置持久化在 Docker named volume `sec_center_data`

## 📁 项目结构

```
├── app/
│   ├── __init__.py            # Flask工厂
│   ├── routes.py              # 路由 + API + 认证
│   ├── modules/
│   │   ├── brute_force.py     # 暴力破解分析引擎
│   │   ├── security_check.py  # 安全检查引擎
│   │   └── auth.py            # 认证模块(密码/2FA/会话)
│   └── templates/
│       ├── base.html          # 双主题布局框架
│       ├── dashboard.html     # 仪表盘
│       ├── brute_force.html   # 暴力破解详情
│       ├── audit.html         # 安全审计详情
│       ├── login.html         # 登录页(含2FA)
│       └── settings.html      # 设置页(改密码/2FA)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 📌 注意事项

- 容器需要 root 权限运行（读取shadow/日志/iptables）
- IP封禁功能直接操作宿主机iptables
- 首次登录后建议立即修改密码并启用2FA
- 仅供安全审计参考，不替代专业安全工具

## 🙏 致谢

- [Flask](https://flask.palletsprojects.com/) — Web 框架
- [psutil](https://github.com/giampaolo/psutil) — 系统信息
- [pyotp](https://github.com/pyauth/pyotp) — TOTP 二步验证
- [qrcode](https://github.com/lincolnloop/python-qrcode) — 二维码生成
- [Gunicorn](https://gunicorn.org/) — WSGI 服务器

## 📄 License

MIT
