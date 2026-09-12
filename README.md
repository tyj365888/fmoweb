# FMO 网页软电台（fmoweb）

FMO（BG5ESN 业余无线电 MQTT 系统）的网页软电台：浏览器即可收发语音、查看在线台站、回放语音记录，无需专用设备。

本仓库包含：前端（`index.html`）、后端（`fmo_api.py`）、指纹采集代理（`fmo_capture.py`）、自建 CA 工具（`fmo_ca.py`）。

## 功能特性

- **语音收发**：PTT 按住说话，OPUS（高压缩）/ RADPCM（高保真）双编码
- **在线台站**：实时在线 / 峰值、各台站频率与 rig 信息
- **语音记录**：回放、同人折叠、按注册时间过滤
- **两层权限**：呼号 + passcode 守听；三元组（呼号 + UID + 证书指纹）核验后开通发送
- **纯 Web 用户**：注册 → 管理员审核 → 自动 `WEB-` 前缀账号
- **管理员**：注册审核、用户管理（拉黑 / 禁言 / 删除）、邮箱验证码绑定
- **PWA**：可安装到桌面 / 手机

## 架构

单个容器内跑两个进程：

| 进程 | 端口 | 作用 |
|------|------|------|
| `gunicorn fmo_api:app` | 9531 | 网页 + 全部 API |
| `python fmo_capture.py` | 9530 | EMQX 鉴权后端（指纹采集 + 转发 SAS） |

外部依赖：

- **MySQL**：账号 / 身份 / 语音记录
- **EMQX**：MQTT broker（语音、遥测、在线）
- **SAS**：鉴权服务（经 `fmo_capture` 转发，SAS 放行才落库指纹）
- **FAS**：审计（删除 UID 时直接操作挂载的 SQLite，无需 SSH）

## 配置

所有配置从环境变量读取，完整清单见 [`.env.example`](.env.example)。配置分层：

| 内容 | 位置 |
|------|------|
| 密码（MySQL / EMQX / SMTP） | `.env`（私有，勿提交） |
| IP / 域名 / 端口 / 用户名 | `.env`（代码里为空默认值） |
| 服务器域名 | 独立变量 `FMO_SERVER_URL`（网页客户端连接用） |
| 服务器身份（呼号 / UID / 指纹） | 复用 SAS 的 `SAS_*`（compose 里映射） |

> 敏感值**切勿硬编码进源码或提交到仓库**。

## 快速开始

### 1. 生成自建 CA（首次）

```bash
python fmo_ca.py          # 生成 root/intermediate CA 到 ca/
```

将 `root-ca.json` 注册到 SAS 的 roots 目录，建立信任链。

### 2. 准备环境变量

```bash
cp .env.example .env
# 填写 MySQL / EMQX / SMTP 密码、服务器域名等
```

### 3. 构建并运行

```bash
docker build -t fmoweb .
docker run --rm -p 9531:9531 -p 9530:9530 \
  --env-file .env \
  -v "$(pwd)/ca:/app/ca" \
  -v "$(pwd)/avatars:/app/avatars" \
  -v "$(pwd)/fas-data:/fas-data" \
  fmoweb
```

## 持久化数据

| 目录 | 内容 | 说明 |
|------|------|------|
| `ca/` | `root-ca.json` / `root.key` / `intermediate-ca.json` / `intermediate.key` | 自建 CA 材料，**含私钥，勿提交**；须与 SAS 信任的根证书匹配 |
| `avatars/` | 用户头像文件 | |
| `fas-data/` | FAS 审计 SQLite 库 | 挂载用于删除 UID 时清理统计（无需 SSH） |

## 部署

本仓库提供了**完整的 compose.yaml**（SAS + EMQX + FAS + fmoweb 四个服务），可一键部署整套 FMO 系统。详细步骤见 [DEPLOY.md](DEPLOY.md)。

简要步骤：

```bash
cp .env.example .env     # 填写配置
python fmo_ca.py         # 生成自建 CA，把 root-ca.json 注册到 SAS
docker compose up -d --build
```

## 许可

代码公开托管，未声明开源许可证（保留所有权利）。
