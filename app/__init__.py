"""Flask 应用工厂"""
from flask import Flask
from flask_sock import Sock
import os

sock = Sock()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get(
        'SECRET_KEY', 'sec-center-' + os.urandom(16).hex()
    )
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    sock.init_app(app)

    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    from .terminal import register_terminal_ws
    register_terminal_ws(sock)

    return app
