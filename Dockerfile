FROM python:3.12-slim

LABEL maintainer="sj yw"
LABEL description="Linux Security Center - Web security dashboard"

# 安装系统依赖（iptables/ss/find/journalctl/lastb）
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 procps login \
    dbus systemd util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8888

CMD ["gunicorn", "-c", "gunicorn_config.py", "run:app"]
