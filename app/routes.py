"""Web 路由"""
from flask import (
    Blueprint, render_template, jsonify, request,
    redirect, url_for, session, flash
)
from pathlib import Path

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
    """暴力破解详情页"""
    days = int(request.args.get('days', 7))
    days = min(max(days, 1), 30)
    data = analyze_brute_force(days=days, top=50)
    lastb = get_lastb_data(top=50)
    return render_template('brute_force.html', data=data, lastb=lastb,
                           days=days, current_user=get_current_user())


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


@bp.route('/terminal')
@login_required
def terminal():
    """在线终端页面"""
    return render_template('terminal.html', current_user=get_current_user())


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
            'bantime = 3600\n'
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


@bp.route('/api/block-ip', methods=['POST'])
@login_required
def block_ip():
    import subprocess
    ip = request.json.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'msg': 'IP不能为空'})

    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return jsonify({'ok': False, 'msg': 'IP格式错误'})

    try:
        subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                       capture_output=True, timeout=5)
        return jsonify({'ok': True, 'msg': f'已封禁 {ip}'})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)})
