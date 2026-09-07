"""认证模块 - SQLite存储 / 密码验证 / TOTP二步验证 / 会话管理"""
import os
import sqlite3
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

# 数据目录（Docker volume 持久化）
DATA_DIR = Path(os.environ.get('DATA_DIR', '/data'))
DB_FILE = DATA_DIR / 'auth.db'

# 默认凭据（首次启动从环境变量初始化）
DEFAULT_USER = os.environ.get('ADMIN_USER', 'admin')
DEFAULT_PASS = os.environ.get('ADMIN_PASSWORD', 'admin123')


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _get_db():
    """获取 SQLite 连接"""
    _ensure_data_dir()
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    """初始化数据库表 + 首次创建默认用户"""
    _ensure_data_dir()
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            password_hash TEXT  NOT NULL,
            salt        TEXT    NOT NULL,
            totp_secret TEXT,
            twofa_enabled INTEGER DEFAULT 0,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT,
            ip          TEXT,
            success     INTEGER,
            timestamp   INTEGER NOT NULL
        )
    """)
    conn.commit()

    # 检查是否已有用户
    row = conn.execute('SELECT COUNT(*) as cnt FROM users').fetchone()
    if row['cnt'] == 0:
        # 首次运行：创建默认用户
        salt = os.urandom(32).hex()
        pw_hash = hashlib.pbkdf2_hmac(
            'sha256', DEFAULT_PASS.encode(), bytes.fromhex(salt), 100000
        ).hex()
        now = int(time.time())
        conn.execute(
            'INSERT INTO users (username, password_hash, salt, totp_secret, twofa_enabled, created_at, updated_at) '
            'VALUES (?, ?, ?, NULL, 0, ?, ?)',
            (DEFAULT_USER, pw_hash, salt, now, now)
        )
        conn.commit()

    conn.close()
    os.chmod(DB_FILE, 0o600)


def _hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), 100000).hex()


def _log_login(username, ip, success):
    """记录登录日志"""
    try:
        conn = _get_db()
        conn.execute(
            'INSERT INTO login_log (username, ip, success, timestamp) VALUES (?, ?, ?, ?)',
            (username, ip, 1 if success else 0, int(time.time()))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def verify_credentials(username, password):
    """验证用户名密码"""
    _init_db()
    conn = _get_db()
    row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not row:
        _log_login(username, request.remote_addr if request else '', False)
        return False

    pw_hash = _hash_password(password, row['salt'])
    ok = hmac.compare_digest(pw_hash, row['password_hash'])
    _log_login(username, request.remote_addr if request else '', ok)
    return ok


def change_password(old_password, new_password):
    """修改密码"""
    _init_db()
    conn = _get_db()
    row = conn.execute('SELECT * FROM users WHERE username = ?', (get_current_user(),)).fetchone()

    if not row:
        conn.close()
        return False, '用户不存在'

    if not hmac.compare_digest(_hash_password(old_password, row['salt']), row['password_hash']):
        conn.close()
        return False, '旧密码错误'

    salt = os.urandom(32).hex()
    new_hash = _hash_password(new_password, salt)
    conn.execute(
        'UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?',
        (new_hash, salt, int(time.time()), row['id'])
    )
    conn.commit()
    conn.close()
    return True, '密码修改成功'


def is_2fa_enabled():
    _init_db()
    conn = _get_db()
    row = conn.execute('SELECT twofa_enabled, totp_secret FROM users LIMIT 1').fetchone()
    conn.close()
    return row and row['twofa_enabled'] and row['totp_secret']


def verify_2fa(code):
    """验证 TOTP 验证码"""
    _init_db()
    conn = _get_db()
    row = conn.execute('SELECT totp_secret FROM users LIMIT 1').fetchone()
    conn.close()
    if not row or not row['totp_secret']:
        return False
    totp = pyotp.TOTP(row['totp_secret'])
    return totp.verify(code, valid_window=2)


def generate_2fa_secret():
    """生成新的 TOTP 密钥（暂存，待验证后启用）"""
    return pyotp.random_base32()


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
    _init_db()
    conn = _get_db()
    conn.execute(
        'UPDATE users SET totp_secret = ?, twofa_enabled = 1, updated_at = ?',
        (secret, int(time.time()))
    )
    conn.commit()
    conn.close()
    return True, '二步验证已启用'


def disable_2fa():
    """关闭 2FA"""
    _init_db()
    conn = _get_db()
    conn.execute(
        'UPDATE users SET twofa_enabled = 0, updated_at = ?', (int(time.time()),)
    )
    conn.commit()
    conn.close()
    return True, '二步验证已关闭'


def get_current_user():
    """获取当前登录用户名"""
    _init_db()
    conn = _get_db()
    row = conn.execute('SELECT username FROM users LIMIT 1').fetchone()
    conn.close()
    return row['username'] if row else 'admin'


def get_login_history(limit=20):
    """获取登录历史记录"""
    _init_db()
    conn = _get_db()
    rows = conn.execute(
        'SELECT * FROM login_log ORDER BY timestamp DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [{'username': r['username'], 'ip': r['ip'], 'success': bool(r['success']),
             'timestamp': r['timestamp']} for r in rows]


def login_required(f):
    """登录保护装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('main.login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function
