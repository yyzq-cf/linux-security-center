"""认证模块 - 密码验证 / TOTP二步验证 / 会话管理"""
import os
import json
import hashlib
import hmac
import base64
import io
import time
from functools import wraps
from pathlib import Path

import pyotp
import qrcode

from flask import session, redirect, url_for, request

# 配置文件路径（Docker volume 持久化）
DATA_DIR = Path(os.environ.get('DATA_DIR', '/data'))
CONFIG_FILE = DATA_DIR / 'auth_config.json'

# 默认凭据（首次启动从环境变量初始化）
DEFAULT_USER = os.environ.get('ADMIN_USER', 'admin')
DEFAULT_PASS = os.environ.get('ADMIN_PASSWORD', 'admin123')


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_config():
    """加载认证配置"""
    _ensure_data_dir()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    # 首次运行：用环境变量初始化
    config = _init_config(DEFAULT_USER, DEFAULT_PASS)
    _save_config(config)
    return config


def _save_config(config):
    _ensure_data_dir()
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)


def _init_config(username, password):
    salt = os.urandom(32).hex()
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()
    return {
        'username': username,
        'password_hash': pw_hash,
        'salt': salt,
        'totp_secret': None,
        'twofa_enabled': False,
        'created_at': int(time.time()),
    }


def _hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), 100000).hex()


def verify_credentials(username, password):
    """验证用户名密码"""
    config = _load_config()
    if not hmac.compare_digest(config['username'], username):
        return False
    pw_hash = _hash_password(password, config['salt'])
    return hmac.compare_digest(pw_hash, config['password_hash'])


def change_password(old_password, new_password):
    """修改密码"""
    config = _load_config()
    if not hmac.compare_digest(_hash_password(old_password, config['salt']), config['password_hash']):
        return False, '旧密码错误'
    salt = os.urandom(32).hex()
    config['salt'] = salt
    config['password_hash'] = _hash_password(new_password, salt)
    _save_config(config)
    return True, '密码修改成功'


def is_2fa_enabled():
    config = _load_config()
    return config.get('twofa_enabled', False) and config.get('totp_secret')


def verify_2fa(code):
    """验证 TOTP 验证码"""
    config = _load_config()
    secret = config.get('totp_secret')
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=2)


def generate_2fa_secret():
    """生成新的 TOTP 密钥（暂存，待验证后启用）"""
    secret = pyotp.random_base32()
    return secret


def provision_2fa(secret, username):
    """生成 otpauth URI"""
    return pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name='Linux安全中心'
    )


def generate_qr_data_uri(uri):
    """生成 QR 码 data URI（PNG base64）"""
    qr = qrcode.QRCode(version=1, box_size=8, border=2,
                       error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f'data:image/png;base64,{b64}'


def enable_2fa(secret, code):
    """验证码通过后正式启用 2FA"""
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=2):
        return False, '验证码错误'
    config = _load_config()
    config['totp_secret'] = secret
    config['twofa_enabled'] = True
    _save_config(config)
    return True, '二步验证已启用'


def disable_2fa():
    """关闭 2FA"""
    config = _load_config()
    config['totp_secret'] = None
    config['twofa_enabled'] = False
    _save_config(config)
    return True, '二步验证已关闭'


def get_current_user():
    """获取当前登录用户名"""
    config = _load_config()
    return config.get('username', 'admin')


def login_required(f):
    """登录保护装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('main.login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function
