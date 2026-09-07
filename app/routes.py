"""Web 路由"""
from flask import (
    Blueprint, render_template, jsonify, request,
    redirect, url_for, session, flash
)
from pathlib import Path
import os

from .modules.brute_force import analyze_brute_force, get_lastb_data
from .modules.security_check import (
    check_ssh_config, check_firewall, check_listening_ports,
    check_users, check_suid_sgid, check_system_info,
    check_fail2ban, check_security_updates
)
from .modules.auth import (
    verify_credentials, verify_2fa, is_2fa_enabled,
    login_required, get_current_user,
    change_password, generate_2fa_secret, provision_2fa,
    generate_qr_data_uri, enable_2fa, disable_2fa,
)

bp = Blueprint('main', __name__)


# ===== 登录 / 登出 =====

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面（支持2FA两步验证）"""
    next_url = request.args.get('next', '/')

    if session.get('logged_in'):
        return redirect(next_url)

    if request.method == 'POST':
        step = request.form.get('step', '1')

        if step == '1':
            # 步骤1: 验证用户名密码
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            if verify_credentials(username, password):
                session['pre_auth'] = True
                session['username'] = username
                if is_2fa_enabled():
                    # 需要2FA
                    return render_template('login.html',
                                           need_2fa=True,
                                           next_url=next_url)
                else:
                    # 直接登录
                    session['logged_in'] = True
                    session.pop('pre_auth', None)
                    return redirect(next_url)
            else:
                return render_template('login.html',
                                       error='用户名或密码错误',
                                       next_url=next_url)

        elif step == '2':
            # 步骤2: 验证2FA验证码
            if not session.get('pre_auth'):
                return redirect(url_for('main.login'))
            code = request.form.get('code', '')
            if verify_2fa(code):
                session['logged_in'] = True
                session.pop('pre_auth', None)
                return redirect(next_url)
            else:
                return render_template('login.html',
                                       need_2fa=True,
                                       error='验证码错误或已过期',
                                       next_url=next_url)

    return render_template('login.html', next_url=next_url)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))


# ===== 受保护页面 =====

@bp.route('/')
@login_required
def index():
    """Dashboard 仪表盘"""
    brute = analyze_brute_force(days=7, top=10)
    sysinfo = check_system_info()
    ssh = check_ssh_config()
    fw = check_firewall()
    f2b = check_fail2ban()

    score = 100
    for item in ssh:
        if item['status'] == 'fail':
            score -= 15
        elif item['status'] == 'warn':
            score -= 5
    if not any(f.get('active') for f in fw):
        score -= 20
    if not f2b['active'] and brute['total_failed'] > 100:
        score -= 10
    score = max(score, 0)

    pass_ssh = sum(1 for i in ssh if i['status'] == 'pass')
    fail_ssh = sum(1 for i in ssh if i['status'] == 'fail')
    warn_ssh = sum(1 for i in ssh if i['status'] == 'warn')

    return render_template('dashboard.html',
                           brute=brute, sysinfo=sysinfo, ssh=ssh, fw=fw, f2b=f2b,
                           score=score, pass_ssh=pass_ssh, fail_ssh=fail_ssh,
                           warn_ssh=warn_ssh, current_user=get_current_user())


@bp.route('/brute-force')
@login_required
def brute_force():
    """暴力破解详情页（分页）"""
    import math
    days = int(request.args.get('days', 7))
    days = min(max(days, 1), 30)
    page = max(int(request.args.get('page', 1)), 1)
    per_page = int(request.args.get('per_page', 20))
    if per_page not in (10, 20, 50):
        per_page = 20

    # 获取全量数据
    data = analyze_brute_force(days=days, top=9999)
    lastb = get_lastb_data(top=50)

    # 对 top_ips 分页
    all_ips = data.get('top_ips', [])
    total_ips = len(all_ips)
    total_pages = max(math.ceil(total_ips / per_page), 1)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    page_ips = all_ips[start:end]

    # 对 top_users 分页
    all_users = data.get('top_users', [])
    total_users = len(all_users)
    user_pages = max(math.ceil(total_users / per_page), 1)
    page_users = all_users[start:end]

    # 对 recent_events 分页
    all_events = data.get('recent_events', [])
    total_events = len(all_events)
    event_pages = max(math.ceil(total_events / per_page), 1)
    page_events = all_events[start:end]

    pagination = {
        'page': page, 'per_page': per_page, 'total_pages': total_pages,
        'total_ips': total_ips, 'total_users': total_users, 'total_events': total_events,
        'has_prev': page > 1, 'has_next': page < total_pages,
        'prev_page': page - 1, 'next_page': page + 1,
        'range_start': start + 1 if total_ips > 0 else 0,
        'range_end': min(end, total_ips),
    }

    data['top_ips'] = page_ips
    data['top_users'] = page_users
    data['recent_events'] = page_events

    return render_template('brute_force.html', data=data, lastb=lastb,
                           days=days, pagination=pagination,
                           current_user=get_current_user())


@bp.route('/security-audit')
@login_required
def security_audit():
    """安全审计详情页"""
    ssh = check_ssh_config()
    fw = check_firewall()
    ports = check_listening_ports()
    users = check_users()
    suid = check_suid_sgid()
    f2b = check_fail2ban()
    updates = check_security_updates()
    sysinfo = check_system_info()

    score = 100
    for item in ssh:
        if item['status'] == 'fail':
            score -= 15
        elif item['status'] == 'warn':
            score -= 5
    for u in users:
        if u['status'] == 'fail':
            score -= 15
    if not any(f.get('active') for f in fw):
        score -= 20
    for p in ports:
        if p['risk'] and p['exposure'] == 'public':
            score -= 10
    for s in suid:
        if s['status'] == 'warn':
            score -= 2
    score = max(score, 0)

    counts = {
        'ssh_pass': sum(1 for i in ssh if i['status'] == 'pass'),
        'ssh_fail': sum(1 for i in ssh if i['status'] == 'fail'),
        'ssh_warn': sum(1 for i in ssh if i['status'] == 'warn'),
        'suid_warn': sum(1 for s in suid if s['status'] == 'warn'),
        'public_ports': sum(1 for p in ports if p['exposure'] == 'public'),
    }

    return render_template('audit.html',
                           ssh=ssh, fw=fw, ports=ports, users=users, suid=suid,
                           f2b=f2b, updates=updates, sysinfo=sysinfo,
                           score=score, counts=counts, current_user=get_current_user())


@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """设置页面 - 修改密码 / 2FA"""
    error = None
    success = None
    setup_2fa = False
    totp_secret = None
    qr_data_uri = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'change_password':
            old_pw = request.form.get('old_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')
            if new_pw != confirm_pw:
                error = '两次输入的新密码不一致'
            elif len(new_pw) < 6:
                error = '新密码至少6位'
            else:
                ok, msg = change_password(old_pw, new_pw)
                if ok:
                    success = msg
                else:
                    error = msg

        elif action == 'setup_2fa':
            secret = generate_2fa_secret()
            uri = provision_2fa(secret, get_current_user())
            setup_2fa = True
            totp_secret = secret
            qr_data_uri = generate_qr_data_uri(uri)

        elif action == 'confirm_2fa':
            secret = request.form.get('secret', '')
            code = request.form.get('code', '')
            ok, msg = enable_2fa(secret, code)
            if ok:
                success = msg
            else:
                error = msg

        elif action == 'disable_2fa':
            code = request.form.get('code', '')
            if verify_2fa(code):
                disable_2fa()
                success = '二步验证已关闭'
            else:
                error = '验证码错误'

    return render_template('settings.html',
                           error=error, success=success,
                           setup_2fa=setup_2fa,
                           totp_secret=totp_secret,
                           qr_data_uri=qr_data_uri,
                           twofa_enabled=is_2fa_enabled(),
                           username=get_current_user(),
                           current_user=get_current_user())


# ===== API =====

@bp.route('/api/system-stats')
@login_required
def system_stats():
    """实时系统资源数据 (CPU/内存/Swap/磁盘)"""
    try:
        import psutil
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        return jsonify({
            'cpu_percent': round(psutil.cpu_percent(interval=0.5), 1),
            'cpu_cores': psutil.cpu_count(),
            'mem_percent': round(mem.percent, 1),
            'mem_total': round(mem.total / (1024**3), 1),
            'mem_used': round(mem.used / (1024**3), 1),
            'swap_percent': round(swap.percent, 1),
            'swap_total': round(swap.total / (1024**3), 1),
            'swap_used': round(swap.used / (1024**3), 1),
            'disk_percent': round(disk.percent, 1),
            'disk_total': round(disk.total / (1024**3), 1),
            'disk_used': round(disk.used / (1024**3), 1),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/brute-force')
@login_required
def api_brute_force():
    days = int(request.args.get('days', 7))
    days = min(max(days, 1), 30)
    return jsonify(analyze_brute_force(days=days))


@bp.route('/api/security-audit')
@login_required
def api_security_audit():
    return jsonify({
        'ssh': check_ssh_config(),
        'firewall': check_firewall(),
        'ports': check_listening_ports(),
        'users': check_users(),
        'suid_sgid': check_suid_sgid(),
        'fail2ban': check_fail2ban(),
        'system_info': check_system_info(),
    })


@bp.route('/api/start-fail2ban', methods=['POST'])
@login_required
def start_fail2ban():
    """启动已安装但未运行的 Fail2Ban"""
    import subprocess
    try:
        subprocess.run(['chroot', '/host', 'systemctl', 'enable', 'fail2ban'],
                       capture_output=True, timeout=10)
        r = subprocess.run(['chroot', '/host', 'systemctl', 'start', 'fail2ban'],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return jsonify({'ok': False, 'msg': f'启动失败: {r.stderr[:200]}'})
        return jsonify({'ok': True, 'msg': 'Fail2Ban 已启动并设置开机自启'})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)})


@bp.route('/api/install-fail2ban', methods=['POST'])
@login_required
def install_fail2ban():
    """在线安装 Fail2Ban（通过 chroot 在宿主机执行）"""
    import subprocess, os
    HOST = '/host'
    env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    try:
        # 检测包管理器（在宿主机上）
        r = subprocess.run(['chroot', HOST, 'which', 'apt-get'],
                           capture_output=True, timeout=5)
        if r.returncode == 0:
            pkg_mgr = 'apt'
            cmds = [
                ['chroot', HOST, 'apt-get', 'update', '-y'],
                ['chroot', HOST, 'apt-get', 'install', '-y', 'fail2ban'],
            ]
        else:
            r = subprocess.run(['chroot', HOST, 'which', 'yum'],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                pkg_mgr = 'yum'
                cmds = [
                    ['chroot', HOST, 'yum', 'install', '-y', 'epel-release'],
                    ['chroot', HOST, 'yum', 'install', '-y', 'fail2ban'],
                ]
            else:
                r = subprocess.run(['chroot', HOST, 'which', 'dnf'],
                                   capture_output=True, timeout=5)
                if r.returncode == 0:
                    pkg_mgr = 'dnf'
                    cmds = [
                        ['chroot', HOST, 'dnf', 'install', '-y', 'epel-release'],
                        ['chroot', HOST, 'dnf', 'install', '-y', 'fail2ban'],
                    ]
                else:
                    return jsonify({'ok': False, 'msg': '不支持的系统：未找到 apt/yum/dnf'})

        # 依次执行安装命令
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=180, env=env)
            if r.returncode != 0:
                return jsonify({
                    'ok': False,
                    'msg': f'{pkg_mgr} 执行失败: {(r.stderr or r.stdout)[:300]}'
                })

        # 启动并设置开机自启
        subprocess.run(['chroot', HOST, 'systemctl', 'enable', 'fail2ban'],
                       capture_output=True, timeout=10)
        subprocess.run(['chroot', HOST, 'systemctl', 'start', 'fail2ban'],
                       capture_output=True, timeout=10)

        # 写入默认 sshd jail 配置
        jail_conf = (
            '[sshd]\n'
            'enabled = true\n'
            'port = ssh\n'
            'filter = sshd\n'
            'logpath = /var/log/auth.log\n'
            'maxretry = 5\n'
            'bantime = 2592000\n'
            '\n'
            '[recidive]\n'
            'enabled = true\n'
            'logpath = /var/log/fail2ban.log\n'
            'banaction = iptables-allports\n'
            'bantime = -1\n'
            'findtime = 2592000\n'
            'maxretry = 2\n'
        )
        jail_path = '/etc/fail2ban/jail.d/sshd.local'
        try:
            subprocess.run(['chroot', HOST, 'mkdir', '-p', '/etc/fail2ban/jail.d'],
                           capture_output=True, timeout=10)
            subprocess.run(
                ['chroot', HOST, 'bash', '-c', 'cat > ' + jail_path],
                input=jail_conf, capture_output=True, text=True, timeout=10
            )
            subprocess.run(['chroot', HOST, 'systemctl', 'restart', 'fail2ban'],
                           capture_output=True, timeout=10)
        except Exception:
            pass

        return jsonify({
            'ok': True,
            'msg': 'Fail2Ban 安装成功！已配置 sshd 防护（5次失败封禁1小时）'
        })
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'msg': '安装超时，请稍后重试'})
    except Exception as e:
        return jsonify({'ok': False, 'msg': f'安装失败: {str(e)}'})


def _fail2ban_cmd(args):
    """通过 chroot 执行 fail2ban-client 命令"""
    import subprocess
    use_chroot = os.path.isdir('/host/bin')
    prefix = ['chroot', '/host'] if use_chroot else []
    r = subprocess.run(prefix + ['fail2ban-client'] + args,
                       capture_output=True, text=True, timeout=10)
    return r


@bp.route('/api/block-ip', methods=['POST'])
@login_required
def block_ip():
    """通过 fail2ban 封禁IP"""
    ip = request.json.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'msg': 'IP不能为空'})
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return jsonify({'ok': False, 'msg': 'IP格式错误'})

    jail = request.json.get('jail', 'sshd')
    r = _fail2ban_cmd(['set', jail, 'banip', ip])
    if r.returncode == 0:
        return jsonify({'ok': True, 'msg': f'已通过 fail2ban 封禁 {ip}'})
    return jsonify({'ok': False, 'msg': f'封禁失败: {r.stderr.strip()[:200]}'})


@bp.route('/api/unblock-ip', methods=['POST'])
@login_required
def unblock_ip():
    """通过 fail2ban 解封IP"""
    ip = request.json.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'msg': 'IP不能为空'})

    jail = request.json.get('jail', 'sshd')
    r = _fail2ban_cmd(['set', jail, 'unbanip', ip])
    if r.returncode == 0:
        return jsonify({'ok': True, 'msg': f'已解封 {ip}'})
    return jsonify({'ok': False, 'msg': f'解封失败: {r.stderr.strip()[:200]}'})


@bp.route('/api/block-all-ips', methods=['POST'])
@login_required
def block_all_ips():
    """一键封禁所有攻击IP（通过fail2ban批量封禁）"""
    import subprocess

    # 获取所有攻击IP列表
    data = request.json or {}
    ips = data.get('ips', [])
    jail = data.get('jail', 'sshd')

    # 如果没传IP列表，自动从暴力破解数据获取所有攻击IP
    if not ips:
        brute = analyze_brute_force(days=30, top=200)
        ips = [item['ip'] for item in brute.get('top_ips', [])]

    if not ips:
        return jsonify({'ok': False, 'msg': '没有可封禁的攻击IP'})

    # 获取当前已封禁的IP，避免重复
    r_status = _fail2ban_cmd(['status', jail])
    already_banned = set()
    if r_status.returncode == 0:
        for line in r_status.stdout.splitlines():
            if 'Banned IP list:' in line:
                already_banned = set(line.split(':', 1)[1].strip().split())
                break

    to_ban = [ip for ip in ips if ip not in already_banned]
    if not to_ban:
        return jsonify({'ok': True, 'msg': f'所有{len(already_banned)}个攻击IP均已封禁', 'count': 0})

    # 批量封禁（用fail2ban-client的循环模式，一次调用）
    import subprocess
    use_chroot = os.path.isdir('/host/bin')
    prefix = ['chroot', '/host'] if use_chroot else []
    success = 0
    failed = []
    for ip in to_ban:
        try:
            r = subprocess.run(
                prefix + ['fail2ban-client', 'set', jail, 'banip', ip],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                success += 1
            else:
                failed.append(ip)
        except Exception:
            failed.append(ip)

    msg = f'已封禁 {success}/{len(to_ban)} 个IP'
    if failed:
        msg += f'，失败{len(failed)}个'
    return jsonify({'ok': True, 'msg': msg, 'count': success})


@bp.route('/api/banned-ips')
@login_required
def banned_ips():
    """获取当前已被 fail2ban 封禁的IP列表（含封禁时间和持续时间）"""
    import subprocess, re
    from datetime import datetime, timedelta

    jail = request.args.get('jail', 'sshd')

    # 1. 获取当前封禁IP列表
    r = _fail2ban_cmd(['status', jail])
    if r.returncode != 0:
        return jsonify({'ok': False, 'banned': [], 'msg': 'fail2ban未运行'})

    banned_ips = []
    for line in r.stdout.splitlines():
        if 'Banned IP list:' in line:
            ips = line.split(':', 1)[1].strip()
            banned_ips = [ip.strip() for ip in ips.split() if ip.strip()]
            break

    # 2. 获取 bantime 配置
    r2 = _fail2ban_cmd(['get', jail, 'bantime'])
    bantime = 3600  # 默认1小时
    if r2.returncode == 0:
        try:
            bantime = int(r2.stdout.strip())
        except ValueError:
            pass

    # 3. 从 fail2ban 日志解析每个IP最后封禁时间
    ban_times = {}
    use_chroot = os.path.isdir('/host/bin')
    log_prefix = ['chroot', '/host'] if use_chroot else []
    try:
        r3 = subprocess.run(
            log_prefix + ['grep', 'Ban ', '/var/log/fail2ban.log'],
            capture_output=True, text=True, timeout=5
        )
        ban_re = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*Ban (\d+\.\d+\.\d+\.\d+)')
        for log_line in r3.stdout.splitlines():
            m = ban_re.search(log_line)
            if m:
                ts_str, ip = m.group(1), m.group(2)
                try:
                    ban_times[ip] = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    pass
    except Exception:
        pass

    # 4. 构建结果
    now = datetime.now()
    result = []
    for ip in banned_ips:
        ban_time = ban_times.get(ip)
        if ban_time:
            elapsed = int((now - ban_time).total_seconds())
            remaining = max(bantime - elapsed, 0)
            result.append({
                'ip': ip,
                'ban_time': ban_time.strftime('%Y-%m-%d %H:%M:%S'),
                'elapsed': elapsed,
                'remaining': remaining,
                'bantime': bantime,
            })
        else:
            result.append({
                'ip': ip,
                'ban_time': None,
                'elapsed': None,
                'remaining': None,
                'bantime': bantime,
            })

    # 按封禁时间倒序（最近封的排前面）
    result.sort(key=lambda x: x.get('elapsed') or 0)

    return jsonify({'ok': True, 'banned': result, 'total': len(result)})
