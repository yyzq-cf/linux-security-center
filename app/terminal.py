"""WebSocket 在线终端 — 通过 PTY + chroot 在宿主机上执行命令"""
import os
import pty
import struct
import fcntl
import termios
import select
import signal
import threading
import subprocess
import json
from flask import session


def register_terminal_ws(sock):
    """注册终端 WebSocket 路由"""

    @sock.route('/ws/terminal')
    def terminal_ws(ws):
        """WebSocket 终端处理"""
        if not session.get('logged_in'):
            ws.send(json.dumps({'type': 'error',
                                'data': '\r\n认证失败，请先登录\r\n'}))
            ws.close()
            return

        host_root = '/host'
        use_chroot = os.path.isdir(os.path.join(host_root, 'bin'))

        # 创建 PTY
        try:
            master_fd, slave_fd = pty.openpty()
        except OSError as e:
            ws.send(json.dumps({'type': 'error',
                                'data': f'\r\n无法创建 PTY: {e}\r\n'}))
            ws.close()
            return

        def set_winsize(fd, rows, cols):
            try:
                winsize = struct.pack('HHHH', rows, cols, 0, 0)
                fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass

        set_winsize(slave_fd, 24, 80)

        # 构建 shell 命令
        if use_chroot:
            cmd = ['chroot', host_root, '/bin/bash', '-l']
        else:
            cmd = ['/bin/bash', '-l']

        env = {
            'TERM': 'xterm-256color',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': '/root',
            'LANG': 'en_US.UTF-8',
            'TZ': 'Asia/Shanghai',
            'SHELL': '/bin/bash',
        }

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=os.setsid,
                close_fds=True,
                env=env,
            )
        except Exception as e:
            ws.send(json.dumps({'type': 'error',
                                'data': f'\r\n无法启动 shell: {e}\r\n'}))
            os.close(slave_fd)
            os.close(master_fd)
            ws.close()
            return

        os.close(slave_fd)

        running = True

        def read_pty():
            """后台线程：PTY 输出 → WebSocket"""
            nonlocal running
            while running:
                try:
                    r, _, _ = select.select([master_fd], [], [], 0.5)
                    if r:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        text = data.decode('utf-8', errors='replace')
                        try:
                            ws.send(json.dumps({'type': 'output', 'data': text}))
                        except Exception:
                            break
                except OSError:
                    break
            running = False
            try:
                ws.send(json.dumps({'type': 'exit',
                                    'data': '\r\n\x1b[33m[会话已结束]\x1b[0m\r\n'}))
            except Exception:
                pass
            try:
                ws.close()
            except Exception:
                pass

        reader = threading.Thread(target=read_pty, daemon=True)
        reader.start()

        # 主循环：WebSocket 输入 → PTY
        try:
            while running:
                try:
                    msg = ws.receive(timeout=1)
                except Exception:
                    break
                if msg is None:
                    continue
                try:
                    cmd_data = json.loads(msg)
                    if cmd_data.get('type') == 'input':
                        os.write(master_fd, cmd_data['data'].encode('utf-8'))
                    elif cmd_data.get('type') == 'resize':
                        set_winsize(master_fd,
                                    cmd_data.get('rows', 24),
                                    cmd_data.get('cols', 80))
                except (json.JSONDecodeError, KeyError, TypeError):
                    try:
                        os.write(master_fd, msg.encode('utf-8'))
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            running = False
            try:
                os.close(master_fd)
            except Exception:
                pass
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
