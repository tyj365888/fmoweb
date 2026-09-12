# FMO 完整部署指南

本指南教你从零部署完整的 FMO 系统：**SAS 鉴权 + EMQX + FAS 审计 + fmoweb 网页软电台**，全部跑在 Docker compose 里。

## 前置条件

- 一台 Docker 主机（群晖 / Linux 服务器均可）
- Docker + Docker Compose v2
- 一个可用的 MySQL（5.7+ / 8.0），本 compose 不内置 MySQL，需要外部提供
- 一个公开域名（用于网页访问 + MQTT 连接）

## 一、准备 MySQL

建库、建用户并授权远程访问：

```sql
CREATE DATABASE fmo CHARACTER SET utf8mb4;
CREATE USER 'fmo'@'%' IDENTIFIED BY '你的密码';
GRANT ALL PRIVILEGES ON fmo.* TO 'fmo'@'%';
FLUSH PRIVILEGES;
```

确保 MySQL 的 `bind-address = 0.0.0.0`，允许容器所在主机远程连接。

## 二、配置环境变量

```bash
cp .env.example .env
```

编辑 `.env`，填写：

- `SAS_*`：服务器（FMO 台站）的身份——呼号、UID、证书指纹、MQTT 域名。这些来自你的真实 FMO 设备/服务器。
- `FMOWEB_MYSQL_*`：第一步创建的 MySQL 连接信息。
- `EMQX_DASHBOARD_PASSWORD` / `FMOWEB_EMQX_*`：EMQX 仪表盘账号密码。
- `FMOWEB_SERVER_URL`：网页客户端要连接的公开域名。
- `FMOWEB_SMTP_*`：发邮件用的 SMTP（不填则「忘记密码」不可用）。

## 三、生成自建 CA 并注册到 SAS

```bash
pip install cryptography   # fmo_ca.py 依赖
python fmo_ca.py           # 生成 ca/ 目录（root + intermediate）
```

把生成的 `ca/root-ca.json` 复制到 SAS 的数据目录 `sas-data/roots/` 下，重启 SAS 后即信任该根证书（日志出现 `Loaded Root CA`）。

> `ca/` 里含私钥，**切勿提交到仓库**（已在 `.gitignore` 中）。

## 四、启动

```bash
docker compose up -d --build
```

首次会构建 fmoweb 和 fas 镜像并拉取 sas/emqx，稍等片刻。

## 五、反向代理（域名 + HTTPS）

fmoweb 的网页在 9531 端口，MQTT WebSocket 在 EMQX 的 8083 端口。用 nginx 反代：

```nginx
server {
    listen 443 ssl;
    server_name 你的域名;

    location / {
        proxy_pass http://127.0.0.1:9531;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location /mqtt {
        proxy_pass http://127.0.0.1:8083/mqtt;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 六、验证

1. 打开 `https://你的域名/`，用「呼号 + APRS passcode」登录（守听层）。
2. 若要发言，提交三元组（呼号 + UID + 证书指纹）核验，通过后即可按住说话。
3. 管理员（服务器呼号）在设置面板底部可审核注册、管理用户（拉黑/禁言/删除）。

## 配置变量对照

compose 把 `.env` 里的变量映射成应用读取的 `FMO_*`：

| 应用读取的变量（fmo_api.py） | compose 里的来源 |
|---|---|
| `FMO_SERVER_CALLSIGN` | `SAS_SERVER_CALLSIGN` |
| `FMO_SERVER_UID` | `SAS_SERVER_UID` |
| `FMO_SERVER_URL` | `FMOWEB_SERVER_URL`（独立域名变量） |
| `FMO_SERVER_PORT` | `SAS_MQTT_PORT` |
| `FMO_SERVER_FINGERPRINT` | `SAS_CERT_FINGERPRINT` |
| `FMO_MYSQL_*` | `FMOWEB_MYSQL_*` |
| `FMO_EMQX_*` | `FMOWEB_EMQX_*` |
| `FMO_SMTP_*` | `FMOWEB_SMTP_*` |
| `FMO_ADMIN_*` | `FMOWEB_ADMIN_*` |

## 常见问题

- **EMQX 鉴权失败 / 设备连不上**：确认 compose 里 EMQX 的鉴权 URL 是 `http://fmoweb:9530/capture`，且 `fmoweb` 容器已启动。
- **数据库连接失败**：确认 MySQL 允许远程连接，`.env` 里 `FMOWEB_MYSQL_*` 正确。
- **语音发不出去/收不到**：确认设备证书指纹、UID、呼号与 SAS 配置一致，且网页端已完成三元组核验。
- **忘记密码邮件发不出**：检查 `FMOWEB_SMTP_*` 配置，或改用管理员联系方式找回。
