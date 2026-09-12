FROM python:3.11-slim

# 系统依赖：
#   ffmpeg            —— 服务端 OPUS 语音解码（回放）
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fmo_api.py fmo_capture.py fmo_ca.py index.html manifest.json entrypoint.sh ./
COPY static/ ./static/
RUN chmod +x entrypoint.sh

# 9531 = gunicorn（网页 / API）；9530 = 指纹采集代理（EMQX 鉴权后端）
EXPOSE 9531 9530

CMD ["./entrypoint.sh"]
