"""暴力破解检测模块 - 分析 auth.log / lastb / journal"""
import os
import re
import glob
import gzip
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta


def _read_auth_logs():
    """读取系统认证日志（兼容 Debian/Ubuntu 和 RHEL/CentOS）"""
    lines = []
    # Debian/Ubuntu: /var/log/auth.log*
    for path in sorted(glob.glob('/var/log/auth.log*')):
        try:
            if path.endswith('.gz'):
                lines.extend(gzip_open(path))
            else:
                with open(path, 'r', errors='replace') as f:
                    lines.extend(f.readlines())
        except PermissionError:
            pass
    # RHEL/CentOS: /var/log/secure*
    for path in sorted(glob.glob('/var/log/secure*')):
        try:
            if path.endswith('.gz'):
                lines.extend(gzip_open(path))
            else:
                with open(path, 'r', errors='replace') as f:
                    lines.extend(f.readlines())
        except PermissionError:
            pass
    # journalctl 兜底
    if not lines:
        try:
            import subprocess
            result = subprocess.run(
                ['journalctl', '-u', 'sshd', '--no-pager', '-n', '10000',
                 '--since', '7 days ago'],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.splitlines()
        except Exception:
            pass
    return lines


def gzip_open(path):
    with gzip.open(path, 'rt', errors='replace') as f:
        return f.readlines()


# SSH 日志正则
RE_FAILED_PW = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port \d+'
)
RE_FAILED_KEY = re.compile(
    r'Connection closed by authenticating user (\S+) (\d+\.\d+\.\d+\.\d+) port \d+'
)
RE_INVALID_USER = re.compile(
    r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+'
)
RE_ACCEPTED = re.compile(
    r'Accepted password|Accepted publickey|session opened'
)
RE_DATE_PREFIX = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})')


def analyze_brute_force(days=7, top=20):
    """
    分析暴力破解数据
    返回: dict with stats, top_ips, top_users, timeline, recent_events
    """
    lines = _read_auth_logs()
    now = datetime.now()
    cutoff = now - timedelta(days=days)

    total_failed = 0
    total_accepted = 0
    total_invalid_user = 0
    ip_failures = Counter()
    user_failures = Counter()
    invalid_users = Counter()
    timeline = defaultdict(int)
    recent_events = []
    ip_users = defaultdict(set)

    for line in lines:
        # 提取日期
        date_match = RE_DATE_PREFIX.search(line)
        event_date = None
        if date_match:
            try:
                event_date = datetime.strptime(
                    date_match.group(1) + f' {now.year}', '%b %d %H:%M:%S %Y'
                )
            except ValueError:
                pass

        # Failed password
        m = RE_FAILED_PW.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            total_failed += 1
            ip_failures[ip] += 1
            user_failures[user] += 1
            ip_users[ip].add(user)
            if event_date and event_date >= cutoff:
                key = event_date.strftime('%Y-%m-%d')
                timeline[key] += 1
                if len(recent_events) < 200:
                    recent_events.append({
                        'time': event_date.strftime('%m-%d %H:%M:%S'),
                        'type': 'Failed Password',
                        'user': user,
                        'ip': ip,
                        'raw': line.strip()[:200]
                    })
            continue

        # Invalid user
        m = RE_INVALID_USER.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            total_invalid_user += 1
            invalid_users[user] += 1
            continue

        # Accepted login
        if RE_ACCEPTED.search(line):
            total_accepted += 1

    # 判断高危IP（超过50次失败）
    dangerous_ips = {ip: c for ip, c in ip_failures.items() if c >= 50}

    return {
        'total_failed': total_failed,
        'total_accepted': total_accepted,
        'total_invalid_user': total_invalid_user,
        'unique_attacker_ips': len(ip_failures),
        'dangerous_ip_count': len(dangerous_ips),
        'top_ips': [
            {'ip': ip, 'count': count,
             'users': ', '.join(sorted(ip_users[ip])[:5]),
             'danger': 'high' if count >= 100 else ('medium' if count >= 50 else 'low')}
            for ip, count in ip_failures.most_common(top)
        ],
        'top_users': [
            {'user': u, 'count': c}
            for u, c in user_failures.most_common(top)
        ],
        'top_invalid_users': [
            {'user': u, 'count': c}
            for u, c in invalid_users.most_common(top)
        ],
        'timeline': dict(sorted(timeline.items())),
        'recent_events': list(reversed(recent_events)),
    }


def get_lastb_data(top=20):
    """从 lastb 命令获取登录失败记录"""
    try:
        import subprocess
        result = subprocess.run(
            ['lastb', '-F'], capture_output=True, text=True, timeout=10
        )
        entries = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] != 'btmp':
                entries.append({
                    'user': parts[0],
                    'line': parts[1] if len(parts) > 1 else '',
                    'ip': parts[2] if len(parts) > 2 else '',
                    'raw': line.strip()
                })
            if len(entries) >= top:
                break
        return entries
    except Exception:
        return []
