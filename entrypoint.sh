#!/bin/sh
set -e
cd /app

# 指纹采集代理（EMQX 鉴权后端，端口 9530；读环境变量 FMO_SAS_URL / FMO_MYSQL_*）
python /app/fmo_capture.py &

# 主服务：gunicorn（端口 9531）。用 exec 使其成为 PID 1，正确接收 SIGTERM。
exec gunicorn -w 4 -b 0.0.0.0:9531 --timeout 300 --graceful-timeout 30 fmo_api:app
