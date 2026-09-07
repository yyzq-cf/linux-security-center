"""Flask 应用工厂"""
from flask import Flask
from datetime import timedelta
import os
import json
from pathlib import Path


def _get_secret_key():
    """从持久化存储读取或生成 SECRET_KEY（保证重启后 session 不过期）"""
    data_dir = Path(os.environ.get('DATA_DIR', '/data'))
    data_dir.mkdir(parents=True, exist_ok=True)
    key_file = data_dir / 'secret_key.txt'
    if key_file.exists():
        return key_file.read_text().strip()
    key = os.urandom(32).hex()
    key_file.write_text(key)
    os.chmod(key_file, 0o600)
    return key


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = _get_secret_key()
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # session 持久化：默认浏览器关闭即过期
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
    app.config['SESSION_COOKIE_MAX_AGE'] = 86400  # 1天（秒）

    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app
