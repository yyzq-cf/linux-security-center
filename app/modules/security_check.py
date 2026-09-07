"""安全检查模块 - SSH配置/防火墙/端口扫描/用户审计/SUID等"""
import os
import re
import stat
import socket
import subprocess
from pathlib import Path


def check_ssh_config():
    """检查 SSH 配置安全性"""
    checks = []
    config_path = '/etc/ssh/sshd_config'

    config_text = ''
    try:
        with open(config_path, 'r') as f:
            config_text = f.read()
    except (PermissionError, FileNotFoundError):
        return [{'item': 'SSH配置', 'status': 'warn', 'detail': '无法读取sshd_config'}]

    def get_value(key):
        # 匹配配置项，忽略注释
        for line in config_text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].lower() == key.lower():
                    return parts[1].strip()
        return None

    # PermitRootLogin
    val = get_value('PermitRootLogin')
    if val is None:
        checks.append({'item': 'PermitRootLogin', 'status': 'warn',
                       'detail': '未设置(默认prohibit-password)', 'recommend': '设为no'})
    elif val.lower() in ('no', 'without-password', 'prohibit-password'):
        checks.append({'item': 'PermitRootLogin', 'status': 'pass',
                       'detail': f'{val} (已禁用密码root登录)'})
    else:
        checks.append({'item': 'PermitRootLogin', 'status': 'fail',
                       'detail': f'{val} (允许root直接登录!)', 'recommend': '设为no'})

    # PasswordAuthentication
    val = get_value('PasswordAuthentication')
    if val is None or val.lower() == 'yes':
        checks.append({'item': 'PasswordAuthentication', 'status': 'warn',
                       'detail': '允许密码认证(易被暴力破解)', 'recommend': '改用密钥认证'})
    else:
        checks.append({'item': 'PasswordAuthentication', 'status': 'pass',
                       'detail': '已禁用密码认证(使用密钥)'})

    # Port
    val = get_value('Port')
    if val is None or val == '22':
        checks.append({'item': 'SSH端口', 'status': 'warn',
                       'detail': '使用默认端口22(易被扫描)', 'recommend': '改为非标准端口'})
    else:
        checks.append({'item': 'SSH端口', 'status': 'pass',
                       'detail': f'非标准端口 {val}'})

    # MaxAuthTries
    val = get_value('MaxAuthTries')
    if val is None or int(val) if val and val.isdigit() else 6 > 3:
        checks.append({'item': 'MaxAuthTries', 'status': 'warn',
                       'detail': f'当前: {val or "默认6"}', 'recommend': '设为3'})
    else:
        checks.append({'item': 'MaxAuthTries', 'status': 'pass',
                       'detail': f'{val}'})

    # PubkeyAuthentication
    val = get_value('PubkeyAuthentication')
    if val is None or val.lower() == 'yes':
        checks.append({'item': 'PubkeyAuthentication', 'status': 'pass',
                       'detail': '已启用公钥认证'})
    else:
        checks.append({'item': 'PubkeyAuthentication', 'status': 'fail',
                       'detail': '未启用公钥认证!', 'recommend': '设为yes'})

    # empty passwords
    val = get_value('PermitEmptyPasswords')
    if val is None or val.lower() == 'no':
        checks.append({'item': 'PermitEmptyPasswords', 'status': 'pass',
                       'detail': '已禁用空密码'})
    else:
        checks.append({'item': 'PermitEmptyPasswords', 'status': 'fail',
                       'detail': '允许空密码!!!', 'recommend': '立即设为no'})

    return checks


def check_firewall():
    """检查防火墙状态"""
    results = []

    # iptables
    try:
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0:
            lines = [l for l in result.stdout.splitlines() if l.strip()
                     and not l.startswith('Chain') and l != '']
            has_rules = len(lines) > 0
            results.append({
                'name': 'iptables',
                'active': has_rules,
                'detail': f'{len(lines)} 条规则' if has_rules else '无规则'
            })
    except Exception:
        pass

    # nftables
    try:
        result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            results.append({
                'name': 'nftables',
                'active': True,
                'detail': '已配置规则'
            })
    except Exception:
        pass

    # ufw
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0:
            active = 'active' in result.stdout.lower()
            results.append({
                'name': 'ufw',
                'active': active,
                'detail': result.stdout.splitlines()[0].strip() if result.stdout else ''
            })
    except Exception:
        pass

    # firewalld
    try:
        result = subprocess.run(['firewall-cmd', '--state'], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0:
            results.append({
                'name': 'firewalld',
                'active': True,
                'detail': 'running'
            })
    except Exception:
        pass

    if not results:
        results.append({
            'name': '防火墙',
            'active': False,
            'detail': '未检测到防火墙(iptables/nft/ufw/firewalld)'
        })

    return results


def check_listening_ports():
    """检查监听端口"""
    ports = []
    try:
        result = subprocess.run(['ss', '-tlnp'], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local = parts[3]
                    proto = parts[0]
                    process = parts[5] if len(parts) > 5 else ''

                    # 提取端口
                    port_match = re.search(r':(\d+)$', local)
                    if port_match:
                        port_num = int(port_match.group(1))
                        addr = local[:port_match.start()]

                        # 判断是否对外开放
                        if addr in ('0.0.0.0', '*', '::', ''):
                            exposure = 'public'
                        elif addr == '127.0.0.1' or addr == '::1':
                            exposure = 'local'
                        else:
                            exposure = 'specific'

                        # 危险端口
                        dangerous = {23: 'Telnet', 21: 'FTP', 1433: 'MSSQL',
                                     3306: 'MySQL', 5432: 'PostgreSQL',
                                     6379: 'Redis', 27017: 'MongoDB',
                                     9200: 'Elasticsearch', 11211: 'Memcached'}
                        risk = dangerous.get(port_num, '')

                        ports.append({
                            'proto': proto,
                            'addr': addr or '*',
                            'port': port_num,
                            'process': process,
                            'exposure': exposure,
                            'risk': risk
                        })
        ports.sort(key=lambda x: x['port'])
    except Exception:
        pass
    return ports


def check_users():
    """检查用户和权限"""
    results = []

    # UID 0 用户 (root 级)
    root_users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3:
                    if parts[2] == '0' and parts[0] != 'root':
                        root_users.append(parts[0])
        if root_users:
            results.append({
                'item': 'UID=0 用户',
                'status': 'fail',
                'detail': f'发现额外root权限用户: {", ".join(root_users)}',
                'recommend': '检查并移除'
            })
        else:
            results.append({
                'item': 'UID=0 用户',
                'status': 'pass',
                'detail': '仅root用户拥有UID 0'
            })
    except Exception:
        pass

    # 可登录用户
    login_users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7 and parts[6] not in (
                        '/sbin/nologin', '/bin/false', '/usr/sbin/nologin'):
                    login_users.append(parts[0])
        results.append({
            'item': '可登录用户',
            'status': 'info',
            'detail': f'{len(login_users)} 个可登录用户: {", ".join(login_users[:10])}'
        })
    except Exception:
        pass

    # sudo 组成员
    try:
        with open('/etc/group', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if parts[0] in ('sudo', 'wheel') and len(parts) >= 4:
                    members = parts[3]
                    if members:
                        results.append({
                            'item': f'{parts[0]}组成员',
                            'status': 'info',
                            'detail': f'members: {members}'
                        })
    except Exception:
        pass

    # 空密码检查
    empty_pw = []
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    if parts[1] in ('', '!', '*'):
                        if parts[1] == '':
                            empty_pw.append(parts[0])
        if empty_pw:
            results.append({
                'item': '空密码账户',
                'status': 'fail',
                'detail': f'发现空密码账户: {", ".join(empty_pw)}',
                'recommend': '立即设置密码或锁定'
            })
        else:
            results.append({
                'item': '空密码账户',
                'status': 'pass',
                'detail': '未发现空密码账户'
            })
    except PermissionError:
        results.append({
            'item': '空密码检查',
            'status': 'warn',
            'detail': '无权限读取/etc/shadow'
        })

    return results


def check_suid_sgid():
    """检查SUID/SGID文件"""
    findings = []
    # 常见安全SUID文件白名单
    whitelist = {
        '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/su',
        '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/newgrp',
        '/usr/bin/gpasswd', '/usr/bin/mount', '/usr/bin/umount',
        '/usr/bin/pkexec', '/usr/lib/openssh/ssh-keysign',
        '/usr/sbin/unix_chkpwd', '/usr/bin/fusermount',
        '/usr/bin/fusermount3', '/usr/sbin/pppd',
    }

    try:
        result = subprocess.run(
            ['find', '/', '-xdev', '-type', 'f', '-perm', '/6000', '-print'],
            capture_output=True, text=True, timeout=30
        )
        for path in result.stdout.splitlines():
            path = path.strip()
            if not path:
                continue
            if path in whitelist:
                status = 'pass'
                detail = '系统标准SUID文件'
            else:
                status = 'warn'
                detail = '非标准SUID文件，需检查'
            findings.append({'path': path, 'status': status, 'detail': detail})
    except Exception:
        pass

    return findings


def check_system_info():
    """系统基础信息"""
    info = {}
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    info['os'] = line.split('=', 1)[1].strip().strip('"')
        with open('/etc/hostname', 'r') as f:
            info['hostname'] = f.read().strip()
        info['uptime'] = subprocess.run(
            ['uptime'], capture_output=True, text=True
        ).stdout.strip()
        info['kernel'] = os.uname().release
        info['arch'] = os.uname().machine
    except Exception:
        pass

    # CPU/内存
    try:
        import psutil
        info['cpu_percent'] = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        info['mem_total'] = f'{mem.total // (1024**3)}GB'
        info['mem_used'] = f'{mem.used // (1024**3)}GB'
        info['mem_percent'] = mem.percent
        info['disk_percent'] = psutil.disk_usage('/').percent
        info['cpu_cores'] = psutil.cpu_count()
    except Exception:
        pass

    return info


def check_fail2ban():
    """检查 fail2ban 状态（通过 chroot 检测宿主机）"""
    use_chroot = os.path.isdir('/host/bin')
    prefix = ['chroot', '/host'] if use_chroot else []
    result = {'installed': False, 'active': False, 'jails': []}
    try:
        # 检测是否安装
        r = subprocess.run(prefix + ['which', 'fail2ban-client'],
                           capture_output=True, timeout=5)
        if r.returncode != 0:
            return result
        result['installed'] = True
        # 检测服务状态
        r = subprocess.run(prefix + ['systemctl', 'is-active', 'fail2ban'],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and 'active' in r.stdout:
            result['active'] = True
            # 获取 jail 列表
            r = subprocess.run(prefix + ['fail2ban-client', 'status'],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if 'Jail list:' in line:
                        jails = line.split(':', 1)[1].strip().rstrip('.')
                        result['jails'] = [j.strip() for j in jails.split(',') if j.strip()]
    except Exception:
        pass
    return result


def check_security_updates():
    """检查安全更新（Debian/Ubuntu）"""
    updates = {'available': False, 'count': 0, 'details': []}
    try:
        result = subprocess.run(
            ['apt', 'list', '--upgradable'],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            if '/upgradable' in line or '[upgradable' in line:
                updates['available'] = True
                updates['count'] += 1
                if len(updates['details']) < 20:
                    updates['details'].append(line[:100])
    except Exception:
        pass
    return updates
