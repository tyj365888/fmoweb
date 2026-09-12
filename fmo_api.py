#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FMO 查询/回放 API（监听 9529）+ 软件客户端发证"""
import io
import wave
import struct
import json
import time
import os
import sys
import random
import hashlib
import subprocess
import smtplib
import secrets
import urllib.request
from urllib.parse import quote
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.header import Header
from flask import Flask, request, jsonify, Response, send_file
import pymysql
import base64
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fmo_ca

app = Flask(__name__)


# ===== 配置：从环境变量 / 同目录 .env 读取（敏感信息不硬编码进源码） =====
def _load_env():
    """加载同目录 .env 文件到 os.environ（每行 KEY=VALUE，支持 # 行内注释）。"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                v = v.split('#', 1)[0].strip()
                os.environ.setdefault(k.strip(), v)
    except Exception:
        pass


def _env(key, default=None):
    return os.environ.get(key, default)


_load_env()

DB = dict(
    host=_env('FMO_MYSQL_HOST', '127.0.0.1'),
    port=int(_env('FMO_MYSQL_PORT', '3306')),
    user=_env('FMO_MYSQL_USER', 'fmo'),
    password=_env('FMO_MYSQL_PASSWORD', ''),
    database=_env('FMO_MYSQL_DB', 'fmo'),
    charset='utf8mb4')


def get_conn():
    return pymysql.connect(**DB)


def _client_ip():
    """取客户端 IP（兼容反向代理 X-Forwarded-For）。"""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


def _send_email(to, subject, body):
    """发送邮件（SMTP 配置在 .env）。"""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return False
    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = SMTP_FROM
        msg['To'] = to
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=60)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=60)
            try:
                server.starttls()
            except Exception:
                pass
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [to], msg.as_string())
        try:
            server.quit()
        except Exception:
            pass
        return True
    except Exception:
        return False


_IP_GEO_CACHE = {}


def _ip_location(ip):
    """IP → 归属地（国家/省/市 · 运营商），带内存缓存。"""
    if not ip:
        return None
    if ip in _IP_GEO_CACHE:
        return _IP_GEO_CACHE[ip]
    loc = None
    try:
        req = urllib.request.Request(
            'http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,isp' % quote(ip),
            headers={'User-Agent': 'fmo-web-client'})
        with urllib.request.urlopen(req, timeout=2) as r:
            d = json.loads(r.read().decode('utf-8'))
            if d.get('status') == 'success':
                parts = [d.get('country'), d.get('regionName'), d.get('city')]
                parts = [p for p in parts if p]
                loc = ' '.join(parts)
                if d.get('isp'):
                    loc = (loc + ' · ' + d['isp']) if loc else d['isp']
    except Exception:
        pass
    _IP_GEO_CACHE[ip] = loc
    return loc


# ===== 自建 CA + 发证（软件客户端身份） =====
CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ca')

# 服务器固定身份（软件客户端鉴权目标 + 前端 MQTT 连接信息）——部署方按需改
SERVER_INFO = {
    'targetCallsign': _env('FMO_SERVER_CALLSIGN', ''),
    'targetUID': int(_env('FMO_SERVER_UID', '0')),
    'targetUrl': _env('FMO_SERVER_URL', ''),
    'targetPort': int(_env('FMO_SERVER_PORT', '1883')),
    'serverFingerprint': _env('FMO_SERVER_FINGERPRINT', ''),
    'mqttHost': _env('FMO_SERVER_URL', ''),
    'mqttPort': int(_env('FMO_SERVER_PORT', '1883')),
}

UID_RANGE = (5000, 99999)   # 作者小区间（证书格式文档示例），0xF0000000+ 会被设备固件当有符号负数/超范围丢弃


def aprs_passcode(callsign):
    """APRS passcode（0x73e2 哈希，公开可算），仅首次登录守听用。"""
    cs = callsign.strip().upper()
    h = 0x73e2
    for i in range(0, len(cs), 2):
        h ^= ord(cs[i]) << 8
        if i + 1 < len(cs):
            h ^= ord(cs[i + 1])
    return str(h & 0x7fff)


def _pw_hash(callsign, password):
    return hashlib.sha256((callsign.upper() + ':' + password).encode('utf-8')).hexdigest()


def _valid_password(p):
    """密码规则：≥6 位，含大写、小写、数字。"""
    return (len(p) >= 6 and any(c.isupper() for c in p)
            and any(c.islower() for c in p) and any(c.isdigit() for c in p))


def _load_intermediate():
    with open(os.path.join(CA_DIR, 'intermediate-ca.json'), encoding='utf-8') as f:
        cert = json.load(f)
    with open(os.path.join(CA_DIR, 'intermediate.key'), encoding='utf-8') as f:
        seed = fmo_ca.b64url_decode(f.read().strip())
    return cert, seed


def _pick_uid(cur):
    """分配一个高位新 uid，避开 web_users / device_certs / web_identities 已占用的。"""
    for _ in range(500):
        cand = random.randint(UID_RANGE[0], UID_RANGE[1])
        cur.execute("SELECT 1 FROM web_users WHERE uid=%s", (cand,))
        if cur.fetchone():
            continue
        cur.execute("SELECT 1 FROM device_certs WHERE uid=%s", (cand,))
        if cur.fetchone():
            continue
        cur.execute("SELECT 1 FROM web_identities WHERE uid=%s", (cand,))
        if cur.fetchone():
            continue
        return cand
    return None


def _allocate_identity(callsign, device_id=None, device_name=None, user_agent=None, last_ip=None):
    """给某呼号+设备分配发言身份：同一设备(device_id)永远复用其 uid，不同设备各自独立 uid，互不抢线。
    同时记录设备名称/UA/最后 IP。"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if device_id:
                cur.execute("SELECT uid, user_cert, private_seed FROM web_identities WHERE callsign=%s AND device_id=%s", (callsign, device_id))
                row = cur.fetchone()
                if row and row[1] and row[2]:
                    cur.execute(
                        "UPDATE web_identities SET device_name=%s, user_agent=%s, last_ip=%s WHERE callsign=%s AND device_id=%s",
                        (device_name, user_agent, last_ip, callsign, device_id))
                    conn.commit()
                    return _identity_response(callsign, row)
            new_uid = _pick_uid(cur)
        if new_uid is None:
            return None
        inter_cert, inter_seed = _load_intermediate()
        now = int(time.time())
        user_seed, user_pk = fmo_ca.new_keypair()
        user_cert = fmo_ca.build_user(
            inter_cert, inter_seed, callsign, new_uid, user_pk,
            now, now + 2 * 365 * 24 * 3600)
        fp = fmo_ca.fingerprint(user_cert)
        cert_str = json.dumps(user_cert)
        seed_str = fmo_ca.b64url_encode(user_seed)
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO web_identities (callsign, uid, user_cert, private_seed, fingerprint, device_id, device_name, user_agent, last_ip) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (callsign, new_uid, cert_str, seed_str, fp, device_id, device_name, user_agent, last_ip))
        conn.commit()
        return _identity_response(callsign, (new_uid, cert_str, seed_str))
    finally:
        conn.close()


# EMQX dashboard API（查在线客户端 IP / 拉黑 / 踢下线）
EMQX_API = _env('FMO_EMQX_API', '')
EMQX_USER = _env('FMO_EMQX_USER', 'admin')
EMQX_PASS = _env('FMO_EMQX_PASSWORD', '')

# SMTP（发送邮件，忘记密码用）
SMTP_HOST = _env('FMO_SMTP_HOST', '')
SMTP_PORT = int(_env('FMO_SMTP_PORT', '465'))
SMTP_USER = _env('FMO_SMTP_USER', '')
SMTP_PASSWORD = _env('FMO_SMTP_PASSWORD', '')
SMTP_FROM = _env('FMO_SMTP_FROM', SMTP_USER)

# 管理员联系方式（呼号未绑定邮箱、无法找回密码时提示联系管理员）
ADMIN_WECHAT = _env('FMO_ADMIN_WECHAT', '')
ADMIN_PHONE = _env('FMO_ADMIN_PHONE', '')

# 邮件主题前缀（方便识别 FMO 相关邮件）
MAIL_PREFIX = _env('FMO_MAIL_PREFIX', '[FMO]-')


def _identity_response(callsign, row):
    """row = (uid, user_cert, private_seed) → 身份响应；无有效证书则 None。"""
    if not row or row[0] is None or not row[1] or not row[2]:
        return None
    try:
        user_cert = json.loads(row[1]) if isinstance(row[1], str) else row[1]
    except Exception:
        user_cert = None
    if not user_cert:
        return None
    inter_cert, _ = _load_intermediate()
    return {
        'callsign': callsign,
        'uid': row[0],
        'userCert': user_cert,
        'privateSeed': row[2],
        'interCert': inter_cert,
        'server': SERVER_INFO,
    }


_EMQX_TOKEN_CACHE = {'token': '', 'ts': 0}


def _emqx_token():
    now = time.time()
    if _EMQX_TOKEN_CACHE['token'] and now - _EMQX_TOKEN_CACHE['ts'] < 300:
        return _EMQX_TOKEN_CACHE['token']
    req = urllib.request.Request(
        EMQX_API + '/login',
        data=json.dumps({'username': EMQX_USER, 'password': EMQX_PASS}).encode('utf-8'),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as r:
        token = json.loads(r.read().decode('utf-8')).get('token', '')
    _EMQX_TOKEN_CACHE['token'] = token
    _EMQX_TOKEN_CACHE['ts'] = now
    return token


_EMQX_CLIENTS_CACHE = {'data': None, 'ts': 0}


def _emqx_clients():
    now = time.time()
    if _EMQX_CLIENTS_CACHE['data'] is not None and now - _EMQX_CLIENTS_CACHE['ts'] < 1:
        return _EMQX_CLIENTS_CACHE['data']
    token = _emqx_token()
    if not token:
        return []
    req = urllib.request.Request(
        EMQX_API + '/clients?page=1&limit=10000',
        headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(req, timeout=5) as r:
        data = json.loads(r.read().decode('utf-8')).get('data', [])
    _EMQX_CLIENTS_CACHE['data'] = data
    _EMQX_CLIENTS_CACHE['ts'] = now
    return data


def _emqx_clients_by_uid():
    """返回 {uid(int): [{clientid, ip, connected_at}]}，从 EMQX 在线客户端按 uid 分组。"""
    try:
        m = {}
        for c in _emqx_clients():
            cid = c.get('clientid', '')
            parts = cid.split('-')
            if len(parts) < 4:
                continue
            try:
                uid = int(parts[-2])
            except ValueError:
                continue
            ip = c.get('ip_address') or c.get('peername') or c.get('source_ip') or ''
            m.setdefault(uid, []).append({'clientid': cid, 'ip': ip, 'connected_at': c.get('connected_at', '')})
        return m
    except Exception:
        return {}


def _start_emqx_warm():
    """后台线程预热 EMQX token/clients 缓存，避免身份面板首次打开时阻塞在冷查询。"""
    def _loop():
        while True:
            try:
                _emqx_clients()
            except Exception:
                pass
            time.sleep(5)
    threading.Thread(target=_loop, daemon=True).start()


_start_emqx_warm()


def _emqx_banned_callsigns():
    """EMQX 拉黑列表里的呼号集合（as=username 且未过期）。FMO 后台(FAS)拉黑会同步写入 EMQX。"""
    try:
        token = _emqx_token()
        if not token:
            return set()
        req = urllib.request.Request(
            EMQX_API + '/banned?limit=1000',
            headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode('utf-8')).get('data', [])
        out = set()
        now = time.time()
        for e in data:
            if e.get('as') != 'username':
                continue
            who = (e.get('who') or '').strip().upper()
            if not who:
                continue
            until = e.get('until')
            if until and until != 'infinity':
                try:
                    t = datetime.fromisoformat(until.replace('Z', '+00:00'))
                    if t.timestamp() < now:
                        continue
                except Exception:
                    pass
            out.add(who)
        return out
    except Exception:
        return set()


def _emqx_kick_uid(uid):
    """踢下线所有使用该 uid 的在线客户端。"""
    try:
        token = _emqx_token()
        if not token:
            return
        for c in _emqx_clients():
            cid = c.get('clientid', '')
            parts = cid.split('-')
            if len(parts) >= 4 and parts[-2] == str(uid):
                req = urllib.request.Request(
                    EMQX_API + '/clients/' + cid, method='DELETE',
                    headers={'Authorization': 'Bearer ' + token})
                try:
                    urllib.request.urlopen(req, timeout=5)
                except Exception:
                    pass
    except Exception:
        pass


def _emqx_unban_callsign(callsign):
    """解除 EMQX 里该呼号的 username 拉黑（清理 FAS 同步过来的拉黑记录）。"""
    try:
        token = _emqx_token()
        if not token:
            return
        req = urllib.request.Request(
            EMQX_API + '/banned/username/' + quote(callsign), method='DELETE',
            headers={'Authorization': 'Bearer ' + token})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _fas_cleanup_uid(callsign, uid):
    """清理 FAS SQLite 里该 uid 的在线记录(minute_stats)/主题统计(topic_stats)/审计包(audit_packets)。
    直接操作挂载的 FAS 数据目录（容器与 FAS 同宿主，无需 SSH）。"""
    try:
        cs = ''.join(c for c in callsign if c.isalnum()).upper()
        if not cs:
            return
        p = 'FMO-%s-%s-' % (cs, uid)
        sql = ("DELETE FROM minute_stats WHERE clientid LIKE '%s%%' OR uid='%s';"
               "DELETE FROM topic_stats WHERE clientid LIKE '%s%%' OR uid='%s';"
               "DELETE FROM audit_packets WHERE clientid LIKE '%s%%' OR conn_uid='%s' OR pkt_uid='%s';"
               % (p, uid, p, uid, p, uid, uid))
        import sqlite3
        db = os.environ.get('FMO_FAS_DB', '/fas-data/fmo-audit-service.db')
        conn = sqlite3.connect(db, timeout=5)
        try:
            conn.executescript(sql)
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


_ISSUED_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS issued_identities (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  callsign VARCHAR(16) NOT NULL,
  uid BIGINT UNSIGNED NOT NULL,
  fingerprint CHAR(43) NOT NULL,
  verified_uid BIGINT UNSIGNED NOT NULL,
  issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_uid (uid),
  KEY idx_callsign (callsign)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

_WEB_USERS_SQL = """
CREATE TABLE IF NOT EXISTS web_users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  callsign VARCHAR(16) NOT NULL,
  password_hash VARCHAR(64) NOT NULL DEFAULT '',
  uid BIGINT UNSIGNED DEFAULT NULL,
  user_cert MEDIUMTEXT DEFAULT NULL,
  private_seed VARCHAR(64) DEFAULT NULL,
  verified_uid BIGINT UNSIGNED DEFAULT NULL,
  verified_fingerprint VARCHAR(43) DEFAULT NULL,
  fingerprint VARCHAR(43) DEFAULT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_callsign (callsign),
  UNIQUE KEY uk_uid (uid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

_WEB_IDENTITIES_SQL = """
CREATE TABLE IF NOT EXISTS web_identities (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  callsign VARCHAR(16) NOT NULL,
  uid BIGINT UNSIGNED NOT NULL,
  user_cert MEDIUMTEXT DEFAULT NULL,
  private_seed VARCHAR(64) DEFAULT NULL,
  fingerprint VARCHAR(43) DEFAULT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_uid (uid),
  KEY idx_callsign (callsign)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def _ensure_tables():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(_ISSUED_TABLE_SQL)
            cur.execute(_WEB_USERS_SQL)
            cur.execute(_WEB_IDENTITIES_SQL)
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN verified_fingerprint VARCHAR(43) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN ptt_style VARCHAR(16) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN email VARCHAR(128) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN reset_token VARCHAR(64) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN reset_expiry DATETIME DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN avatar VARCHAR(255) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN account_type VARCHAR(16) DEFAULT 'callsign'")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN status VARCHAR(16) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN email_code VARCHAR(16) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN email_code_expiry DATETIME DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN banned TINYINT(1) DEFAULT 0")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_users ADD COLUMN muted TINYINT(1) DEFAULT 0")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_identities ADD COLUMN device_id VARCHAR(64) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_identities ADD COLUMN device_name VARCHAR(128) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_identities ADD COLUMN user_agent VARCHAR(512) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_identities ADD COLUMN last_ip VARCHAR(64) DEFAULT NULL")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE web_identities ADD COLUMN remark VARCHAR(128) DEFAULT NULL")
            except Exception:
                pass
            # 迁移：把 web_users 里的旧身份搬到 web_identities（多端多 UID 改造）
            cur.execute("SELECT callsign, uid, user_cert, private_seed, fingerprint FROM web_users WHERE uid IS NOT NULL AND user_cert IS NOT NULL AND private_seed IS NOT NULL")
            for cs, uid, cert, seed, fp in cur.fetchall():
                cur.execute("INSERT IGNORE INTO web_identities (callsign, uid, user_cert, private_seed, fingerprint) VALUES (%s,%s,%s,%s,%s)",
                            (cs, uid, cert, seed, fp))
        conn.commit()
    finally:
        conn.close()


try:
    _ensure_tables()
except Exception as e:
    print('[fmo_api] 建表失败: %r' % (e,))


# ===== IMA ADPCM（RADPCM）解码 =====
IMA_STEP_TABLE = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34,
    37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
    157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494,
    544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552,
    1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428,
    4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
    12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086,
    29794, 32767]
IMA_INDEX_TABLE = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8]


def ima_decode(code, step_idx, predictor):
    step = IMA_STEP_TABLE[step_idx]
    delta = step >> 3
    if code & 1:
        delta += step >> 2
    if code & 2:
        delta += step >> 1
    if code & 4:
        delta += step
    if code & 8:
        predictor -= delta
    else:
        predictor += delta
    predictor = max(-32768, min(32767, predictor))
    step_idx = max(0, min(88, step_idx + IMA_INDEX_TABLE[code]))
    return predictor, step_idx


def decode_radpcm(audio):
    """RADPCM 帧(328B: 8B头+320B数据) → 640 个 16bit PCM 样本"""
    if len(audio) < 8:
        return []
    recover_pcm = struct.unpack('<h', audio[2:4])[0]
    step_idx = audio[4]
    adpcm_bytes = struct.unpack('<H', audio[6:8])[0]
    data = audio[8:8 + adpcm_bytes]
    predictor = recover_pcm
    samples = []
    for byte in data:
        predictor, step_idx = ima_decode((byte >> 4) & 0xF, step_idx, predictor)
        samples.append(predictor)
        predictor, step_idx = ima_decode(byte & 0xF, step_idx, predictor)
        samples.append(predictor)
    return samples


def _ogg_crc(data):
    """Ogg 页 CRC（多项式 0x04C11DB7、初值 0、非反射），不是标准 zlib CRC。"""
    crc = 0
    for b in data:
        crc ^= (b << 24)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (crc & 0x80000000) else (crc << 1) & 0xFFFFFFFF
    return crc


def _ogg_page(packets, header_type, granule, seq, serial):
    seg = bytearray()
    for p in packets:
        seg.append(len(p))
    hdr = (b'OggS' + b'\x00' + bytes([header_type]) + struct.pack('<q', granule) +
           struct.pack('<I', serial) + struct.pack('<I', seq) + b'\x00\x00\x00\x00' +
           bytes([len(seg)]) + bytes(seg))
    body = hdr + b''.join(packets)
    crc = _ogg_crc(body)
    return body[:22] + struct.pack('<I', crc) + body[26:]


def decode_opus_frames(frames):
    """把一串原始 Opus 包（20ms/帧）拼成最小 Ogg Opus 容器，用 ffmpeg 解成 16kHz PCM。"""
    serial = 12345
    opus_head = b'OpusHead' + b'\x01\x01' + struct.pack('<H', 0) + struct.pack('<I', 48000) + struct.pack('<h', 0) + b'\x00'
    opus_tags = b'OpusTags' + struct.pack('<I', 0) + struct.pack('<I', 0)
    buf = _ogg_page([opus_head], 0x02, 0, 0, serial)
    buf += _ogg_page([opus_tags], 0x00, 0, 1, serial)
    gran = 0
    for i, p in enumerate(frames):
        gran += 960  # 20ms @48kHz
        ht = 0x04 if i == len(frames) - 1 else 0x00
        buf += _ogg_page([p], ht, gran, 2 + i, serial)
    try:
        r = subprocess.run(
            ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-f', 'ogg', '-i', 'pipe:0',
             '-f', 's16le', '-ac', '1', '-ar', '16000', '-'],
            input=buf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if r.returncode != 0 or not r.stdout:
            return []
        return list(struct.unpack('<%dh' % (len(r.stdout) // 2), r.stdout))
    except Exception:
        return []


def frames_to_wav(frames, mode=2):
    """frames: list[audio bytes]。mode: 1=OPUS，2=RADPCM。输出 16kHz WAV。"""
    if mode == 1:
        pcm = decode_opus_frames(frames)   # 已 16kHz
    else:
        pcm = []
        for audio in frames:
            pcm.extend(decode_radpcm(audio))  # 8kHz
    if not pcm:
        return None
    # 去直流（减整体均值）——设备 ADC 带有直流偏置
    mean = sum(pcm) / len(pcm)
    pcm = [max(-32768, min(32767, int(round(s - mean)))) for s in pcm]
    # 峰值归一化：把内容放大到可听音量（纯静音 peak 很小则不放大）
    peak = max((abs(s) for s in pcm), default=0)
    if peak > 400:
        gain = 0.85 * 32767.0 / peak
        pcm = [max(-32768, min(32767, int(round(s * gain)))) for s in pcm]
    # RADPCM 上采样 8k→16k（线性插值）；OPUS 已 16kHz 无需
    if mode != 1:
        up = []
        if len(pcm) > 1:
            for i in range(len(pcm) - 1):
                up.append(pcm[i])
                up.append((pcm[i] + pcm[i + 1]) // 2)
            up.append(pcm[-1])
        else:
            up = pcm
        pcm = up
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(16000)
        w.writeframes(b''.join(struct.pack('<h', s) for s in pcm))
    return buf.getvalue()


# ===== API 端点 =====
@app.route('/api/issue', methods=['POST'])
def issue_identity():
    """三元组（呼号+UID+指纹）核验真实设备连接记录后，签发软件客户端身份。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    fingerprint = (body.get('fingerprint') or '').strip()
    try:
        orig_uid = int(body.get('uid'))
    except (TypeError, ValueError):
        return jsonify({'error': 'uid 无效'}), 400
    if not callsign or not fingerprint:
        return jsonify({'error': '呼号/指纹不能为空'}), 400

    # 1. 三元组比对真实设备连接记录
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM device_certs WHERE callsign=%s AND uid=%s AND fingerprint=%s",
                (callsign, orig_uid, fingerprint))
            if not cur.fetchone():
                return jsonify({'error': '三元组核验失败：呼号+UID+指纹未匹配到真实设备连接记录'}), 403
    finally:
        conn.close()

    # 2. 分配发言身份（同一设备复用其 uid，否则新建），并记录设备信息
    device_id = (body.get('device_id') or '').strip() or None
    device_name = (body.get('device_name') or '').strip() or None
    user_agent = (body.get('user_agent') or '')[:512] or None
    identity = _allocate_identity(callsign, device_id, device_name, user_agent, _client_ip())
    if identity is None:
        return jsonify({'error': '无可用 UID（高位区间耗尽）'}), 500

    # 3. 记录已核验的真实设备（用于下次登录发身份 / 设置页回填）
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO web_users (callsign, verified_uid, verified_fingerprint) VALUES (%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE verified_uid=VALUES(verified_uid), verified_fingerprint=VALUES(verified_fingerprint)",
                (callsign, orig_uid, fingerprint))
        conn.commit()
    finally:
        conn.close()

    # 4. 未设密码则强制设密码（放在核验通过之后，避免抢注）
    need_pw = False
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
            need_pw = not (row and row[0])
    finally:
        conn.close()

    resp = dict(identity)
    resp['needPassword'] = need_pw
    return jsonify(resp)


@app.route('/api/register', methods=['POST'])
def register():
    """普通 Web 用户注册：用户名(6-8 位字母数字)+密码+邮箱，注册后需审核通过才能登录。"""
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get('username') or '').strip()
    password = (body.get('password') or '')
    email = (body.get('email') or '').strip()[:128]
    if not (6 <= len(username) <= 8) or not username.isalnum():
        return jsonify({'error': '用户名需 6-8 位字母或数字'}), 400
    if not _valid_password(password):
        return jsonify({'error': '密码至少 6 位，需包含大写字母、小写字母和数字'}), 400
    if not email or '@' not in email:
        return jsonify({'error': '请填写有效邮箱'}), 400
    callsign = 'WEB-' + username.upper()
    h = _pw_hash(callsign, password)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT callsign FROM web_users WHERE callsign=%s", (callsign,))
            if cur.fetchone():
                return jsonify({'error': '该用户名已被注册'}), 409
            cur.execute("INSERT INTO web_users (callsign, password_hash, account_type, status, email) VALUES (%s,%s,'web','pending',%s)",
                        (callsign, h, email))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'message': '注册成功，请等待管理员审核'})


@app.route('/api/login', methods=['POST'])
def login():
    """登录：呼号用户→验密码/passcode；普通 Web 用户(callsign 以 WEB- 开头)→验密码+审核状态。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    secret = (body.get('secret') or '').strip()
    if not callsign or not secret:
        return jsonify({'error': '呼号/用户名与密码不能为空'}), 400

    # 黑名单：拉黑的呼号禁止登录（FMO 后台/FAS 拉黑，同步在 EMQX /banned）
    if callsign in _emqx_banned_callsigns():
        return jsonify({'error': '该账户已被拉黑，禁止登录'}), 403

    is_web = callsign.startswith('WEB-')

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, verified_uid, ptt_style, account_type, status, banned, muted FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
    finally:
        conn.close()

    ptt_style = (row[2] if row and row[2] else 'round')
    is_banned = bool(row[5]) if row else False
    is_muted = bool(row[6]) if row else False
    if is_banned:
        return jsonify({'error': '该账户已被管理员拉黑，禁止登录'}), 403

    if is_web:
        # 普通 Web 用户：必须审核通过才能登录
        if not row:
            return jsonify({'error': '用户名未注册'}), 401
        if row[3] != 'web' or row[4] != 'approved':
            if row[4] == 'pending':
                return jsonify({'error': '账号正在审核中，请等待管理员审核通过'}), 403
            return jsonify({'error': '账号未通过审核'}), 403
        if row[0] and _pw_hash(callsign, secret) == row[0]:
            device_id = (body.get('device_id') or '').strip() or None
            device_name = (body.get('device_name') or '').strip() or None
            user_agent = (body.get('user_agent') or '')[:512] or None
            identity = _allocate_identity(callsign, device_id, device_name, user_agent, _client_ip())
            return jsonify({'callsign': callsign, 'identity': identity, 'ptt_style': ptt_style, 'tier': 'web', 'muted': is_muted})
        return jsonify({'error': '密码不正确'}), 401

    if row and row[0]:
        # 已设密码 → 只认密码，passcode 失效；核验过的呼号每次登录分配一个发言身份（绑设备 device_id）
        if _pw_hash(callsign, secret) == row[0]:
            device_id = (body.get('device_id') or '').strip() or None
            device_name = (body.get('device_name') or '').strip() or None
            user_agent = (body.get('user_agent') or '')[:512] or None
            identity = _allocate_identity(callsign, device_id, device_name, user_agent, _client_ip()) if (row[1] is not None) else None
            return jsonify({'callsign': callsign, 'identity': identity, 'ptt_style': ptt_style, 'tier': 'full', 'muted': is_muted})
        return jsonify({'error': '密码不正确'}), 401
    # 未设密码 → passcode 登录（守听层：只查看，不播放/发送，不强制改密码）
    if secret == aprs_passcode(callsign):
        return jsonify({'callsign': callsign, 'ptt_style': ptt_style, 'tier': 'listen', 'muted': is_muted})
    return jsonify({'error': 'passcode 不正确'}), 401


@app.route('/api/admin/pending-users')
def admin_pending_users():
    """管理员：列出待审核的普通 Web 用户。"""
    admin = (request.args.get('admin') or '').strip().upper()
    if admin != SERVER_INFO['targetCallsign']:
        return jsonify({'error': '无权限'}), 403
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT callsign, email, created_at FROM web_users WHERE account_type='web' AND status='pending' ORDER BY created_at")
            rows = cur.fetchall()
    finally:
        conn.close()
    items = [{'callsign': r[0], 'email': r[1], 'created_at': r[2].strftime('%Y-%m-%d %H:%M:%S') if r[2] else None} for r in rows]
    return jsonify({'items': items})


@app.route('/api/admin/review', methods=['POST'])
def admin_review():
    """管理员：审核普通 Web 用户（approve / reject）。"""
    body = request.get_json(force=True, silent=True) or {}
    admin = (body.get('admin') or '').strip().upper()
    callsign = (body.get('callsign') or '').strip().upper()
    action = (body.get('action') or '').strip().lower()
    if admin != SERVER_INFO['targetCallsign']:
        return jsonify({'error': '无权限'}), 403
    if action not in ('approve', 'reject'):
        return jsonify({'error': '无效操作'}), 400
    new_status = 'approved' if action == 'approve' else 'rejected'
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM web_users WHERE callsign=%s AND account_type='web'", (callsign,))
            if not cur.fetchone():
                return jsonify({'error': '用户不存在'}), 404
            cur.execute("UPDATE web_users SET status=%s WHERE callsign=%s", (new_status, callsign))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/admin/users')
def admin_users():
    """管理员：列出除管理员外的所有用户（含拉黑/禁言状态）。"""
    admin = (request.args.get('admin') or '').strip().upper()
    if admin != SERVER_INFO['targetCallsign']:
        return jsonify({'error': '无权限'}), 403
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT callsign, account_type, status, banned, muted, created_at FROM web_users WHERE callsign != %s ORDER BY created_at DESC", (SERVER_INFO['targetCallsign'],))
            rows = cur.fetchall()
    finally:
        conn.close()
    items = [{'callsign': r[0], 'account_type': r[1], 'status': r[2], 'banned': bool(r[3]), 'muted': bool(r[4]), 'created_at': r[5].strftime('%Y-%m-%d %H:%M:%S') if r[5] else None} for r in rows]
    return jsonify({'items': items})


@app.route('/api/admin/ban', methods=['POST'])
def admin_ban():
    """管理员：拉黑/取消拉黑用户（拉黑后禁止登录）。"""
    body = request.get_json(force=True, silent=True) or {}
    admin = (body.get('admin') or '').strip().upper()
    callsign = (body.get('callsign') or '').strip().upper()
    banned = bool(body.get('banned'))
    if admin != SERVER_INFO['targetCallsign']:
        return jsonify({'error': '无权限'}), 403
    if not callsign or callsign == SERVER_INFO['targetCallsign']:
        return jsonify({'error': '不能操作管理员自己'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM web_users WHERE callsign=%s", (callsign,))
            if not cur.fetchone():
                return jsonify({'error': '用户不存在'}), 404
            cur.execute("UPDATE web_users SET banned=%s WHERE callsign=%s", (1 if banned else 0, callsign))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/admin/mute', methods=['POST'])
def admin_mute():
    """管理员：禁言/解除禁言用户（禁言后只能收听，不能发送）。"""
    body = request.get_json(force=True, silent=True) or {}
    admin = (body.get('admin') or '').strip().upper()
    callsign = (body.get('callsign') or '').strip().upper()
    muted = bool(body.get('muted'))
    if admin != SERVER_INFO['targetCallsign']:
        return jsonify({'error': '无权限'}), 403
    if not callsign or callsign == SERVER_INFO['targetCallsign']:
        return jsonify({'error': '不能操作管理员自己'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM web_users WHERE callsign=%s", (callsign,))
            if not cur.fetchone():
                return jsonify({'error': '用户不存在'}), 404
            cur.execute("UPDATE web_users SET muted=%s WHERE callsign=%s", (1 if muted else 0, callsign))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/admin/delete-user', methods=['POST'])
def admin_delete_user():
    """管理员：删除用户（账号 + 软件身份 + 三元组核验记录）。"""
    body = request.get_json(force=True, silent=True) or {}
    admin = (body.get('admin') or '').strip().upper()
    callsign = (body.get('callsign') or '').strip().upper()
    if admin != SERVER_INFO['targetCallsign']:
        return jsonify({'error': '无权限'}), 403
    if not callsign or callsign == SERVER_INFO['targetCallsign']:
        return jsonify({'error': '不能删除管理员自己'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM web_users WHERE callsign=%s", (callsign,))
            if not cur.fetchone():
                return jsonify({'error': '用户不存在'}), 404
            cur.execute("DELETE FROM web_identities WHERE callsign=%s", (callsign,))
            cur.execute("DELETE FROM device_certs WHERE callsign=%s", (callsign,))
            cur.execute("DELETE FROM web_users WHERE callsign=%s", (callsign,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/set-password', methods=['POST'])
def set_password():
    """设置/修改登录密码。首次设密码需先核验真实设备（避免抢注）；已设密码可直接改。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    password = (body.get('password') or '')
    if not callsign or not _valid_password(password):
        return jsonify({'error': '密码至少 6 位，需包含大写字母、小写字母和数字'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, verified_uid FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
    finally:
        conn.close()
    has_pw = bool(row and row[0])
    verified = bool(row and row[1] is not None)
    if not has_pw:
        if not verified:
            return jsonify({'error': '请先核验真实设备（UID+指纹）再设置密码'}), 403
    else:
        old_password = (body.get('old_password') or '')
        if _pw_hash(callsign, old_password) != row[0]:
            return jsonify({'error': '旧密码不正确'}), 403
    h = _pw_hash(callsign, password)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO web_users (callsign, password_hash) VALUES (%s,%s) "
                "ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash)",
                (callsign, h))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/email/send-code', methods=['POST'])
def email_send_code():
    """发送邮箱验证码（6 位数字），存到 web_users.email_code（10 分钟有效）。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    email = (body.get('email') or '').strip()
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    if not email or '@' not in email:
        return jsonify({'error': '请输入有效邮箱'}), 400
    code = '%06d' % random.randint(0, 999999)
    expiry = datetime.now() + timedelta(minutes=10)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO web_users (callsign, email_code, email_code_expiry) VALUES (%s,%s,%s) "
                        "ON DUPLICATE KEY UPDATE email_code=VALUES(email_code), email_code_expiry=VALUES(email_code_expiry)",
                        (callsign, code, expiry))
        conn.commit()
    finally:
        conn.close()
    if not _send_email(email, MAIL_PREFIX + '邮箱验证码', '您的 FMO 邮箱验证码：%s（10 分钟内有效，请勿泄露）' % code):
        return jsonify({'error': '验证码邮件发送失败，请检查邮箱或稍后重试'}), 500
    return jsonify({'ok': True, 'message': '验证码已发送到邮箱，10 分钟内有效'})


@app.route('/api/email/verify', methods=['POST'])
def email_verify():
    """验证邮箱验证码，通过后保存邮箱。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    email = (body.get('email') or '').strip()
    code = (body.get('code') or '').strip()
    if not callsign or not code:
        return jsonify({'error': '参数不完整'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT email_code, email_code_expiry FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
            if not row or not row[0]:
                return jsonify({'error': '请先发送验证码'}), 400
            if row[1] and datetime.now() > row[1]:
                return jsonify({'error': '验证码已过期，请重新发送'}), 400
            if row[0] != code:
                return jsonify({'error': '验证码不正确'}), 400
            cur.execute("UPDATE web_users SET email=%s, email_code=NULL, email_code_expiry=NULL WHERE callsign=%s", (email, callsign))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/email/<callsign>')
def get_email(callsign):
    callsign = callsign.strip().upper()
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
        return jsonify({'callsign': callsign, 'email': (row[0] if row and row[0] else '')})
    finally:
        conn.close()


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """忘记密码：生成重置验证码并邮件发送（需已绑定邮箱）。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
    finally:
        conn.close()
    email = row[0] if row and row[0] else None
    if not email:
        return jsonify({'error': '该呼号未绑定邮箱，无法找回密码，请联系管理员', 'admin_wechat': ADMIN_WECHAT, 'admin_phone': ADMIN_PHONE}), 400
    token = secrets.token_hex(16)
    expiry = datetime.now() + timedelta(minutes=30)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE web_users SET reset_token=%s, reset_expiry=%s WHERE callsign=%s", (token, expiry, callsign))
        conn.commit()
    finally:
        conn.close()
    reset_url = 'https://%s/?reset=%s&callsign=%s' % (SERVER_INFO['targetUrl'], token, callsign)
    body = '您好，请点击以下链接重置 FMO 网页软电台密码（30 分钟内有效）：\n\n%s\n\n如果无法点击，可复制该验证码手动输入：%s' % (reset_url, token)
    if not _send_email(email, MAIL_PREFIX + '密码重置', body):
        return jsonify({'error': '邮件发送失败（请检查 SMTP 配置）'}), 500
    return jsonify({'ok': True})


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """用重置验证码设置新密码。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    token = (body.get('token') or '').strip()
    password = (body.get('password') or '')
    if not callsign or not token or not _valid_password(password):
        return jsonify({'error': '密码至少 6 位，需包含大写字母、小写字母和数字'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT reset_token, reset_expiry FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
            if not row or not row[0] or row[0] != token:
                return jsonify({'error': '验证码错误'}), 403
            if row[1] is None or row[1] < datetime.now():
                return jsonify({'error': '验证码已过期'}), 403
            cur.execute("UPDATE web_users SET password_hash=%s, reset_token=NULL, reset_expiry=NULL WHERE callsign=%s", (_pw_hash(callsign, password), callsign))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/prefs/ptt-style', methods=['POST'])
def prefs_ptt_style():
    """保存该呼号的 PTT 按钮样式偏好（跨设备统一）。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    style = (body.get('style') or '').strip()[:16] or 'round'
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO web_users (callsign, ptt_style) VALUES (%s,%s) ON DUPLICATE KEY UPDATE ptt_style=VALUES(ptt_style)", (callsign, style))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/identity/status')
def identity_status():
    """返回该呼号已核验的真实设备 + 所有 UID（真实设备+软件身份）及在线状态/IP/注册/最后在线。"""
    callsign = (request.args.get('callsign') or '').strip().upper()
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT verified_uid, verified_fingerprint FROM web_users WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
            cur.execute("SELECT uid, fingerprint, first_seen, last_seen FROM device_certs WHERE callsign=%s ORDER BY uid", (callsign,))
            dev_rows = cur.fetchall()
            cur.execute("SELECT uid, fingerprint, created_at, device_name, user_agent, last_ip, remark FROM web_identities WHERE callsign=%s ORDER BY uid", (callsign,))
            id_rows = cur.fetchall()
    finally:
        conn.close()

    clients_by_uid = _emqx_clients_by_uid()

    def _fmt(dt):
        if dt is None:
            return None
        if hasattr(dt, 'strftime'):
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        return str(dt)

    verified = None
    if row and row[0] is not None:
        verified = {'uid': row[0], 'fingerprint': row[1]}
    if verified is None:
        real_devs = [(r[0], r[1]) for r in dev_rows if r[0] < UID_RANGE[0]]
        if real_devs:
            real_devs.sort(key=lambda r: (0 if r[0] in clients_by_uid else 1, r[0]))
            verified = {'uid': real_devs[0][0], 'fingerprint': real_devs[0][1]}

    dev_map = {}
    for duid, dfp, dfirst, dlast in dev_rows:
        dev_map[duid] = {'fingerprint': dfp, 'first_seen': _fmt(dfirst), 'last_seen': _fmt(dlast)}
    id_map = {}
    for uid, fp, created, dname, ua, lip, remark in id_rows:
        id_map[uid] = {'fingerprint': fp, 'first_seen': _fmt(created), 'device_name': dname, 'user_agent': ua, 'last_ip': lip, 'remark': remark}

    uids = []
    for uid in sorted(set(list(dev_map) + list(id_map))):
        dev = dev_map.get(uid, {})
        ident = id_map.get(uid, {})
        clist = clients_by_uid.get(uid, [])
        uids.append({
            'uid': uid,
            'fingerprint': ident.get('fingerprint') or dev.get('fingerprint'),
            'kind': 'software' if uid >= UID_RANGE[0] else 'device',
            'online': uid in clients_by_uid,
            'clients': clist,
            'first_seen': ident.get('first_seen') or dev.get('first_seen'),
            'last_seen': dev.get('last_seen'),
            'device_name': ident.get('device_name'),
            'user_agent': ident.get('user_agent'),
            'last_ip': ident.get('last_ip'),
            'ip_location': None,
            'remark': ident.get('remark'),
            '_geo_ip': clist[0].get('ip') if clist else ident.get('last_ip'),
        })

    # 归属地并发查询（去重后并行，避免多个 UID 串行各 2s）
    _unique_ips = list(set(u['_geo_ip'] for u in uids if u.get('_geo_ip')))
    _geo_map = {}
    if _unique_ips:
        with ThreadPoolExecutor(max_workers=min(8, len(_unique_ips))) as _ex:
            for _ip, _loc in zip(_unique_ips, _ex.map(_ip_location, _unique_ips)):
                _geo_map[_ip] = _loc
    for u in uids:
        u['ip_location'] = _geo_map.get(u.pop('_geo_ip', None))

    return jsonify({'callsign': callsign, 'verified': verified, 'uids': uids})


@app.route('/api/identity/delete', methods=['POST'])
def identity_delete():
    """删除该呼号的全部软件身份（保留密码 + 已核验的真实设备信息）。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM web_identities WHERE callsign=%s", (callsign,))
            cur.execute("UPDATE web_users SET uid=NULL, user_cert=NULL, private_seed=NULL, fingerprint=NULL WHERE callsign=%s", (callsign,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/uid/delete', methods=['POST'])
def uid_delete():
    """删除该呼号下某个软件 UID（真实删除，释放给其它设备用）；在线则先踢下线，并清理 FAS/EMQX 拉黑。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    try:
        uid = int(body.get('uid'))
    except (TypeError, ValueError):
        return jsonify({'error': 'uid 无效'}), 400
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    if uid < UID_RANGE[0]:
        return jsonify({'error': '真实设备 UID 不能删除'}), 403

    _emqx_kick_uid(uid)

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM device_certs WHERE callsign=%s AND uid=%s", (callsign, uid))
            cur.execute("DELETE FROM web_identities WHERE callsign=%s AND uid=%s", (callsign, uid))
            cur.execute("UPDATE web_users SET uid=NULL, user_cert=NULL, private_seed=NULL, fingerprint=NULL WHERE callsign=%s AND uid=%s", (callsign, uid))
        conn.commit()
    finally:
        conn.close()

    # 清理 FAS/EMQX 里该呼号的拉黑记录 + 在线记录/主题统计/审计包
    _emqx_unban_callsign(callsign)
    _fas_cleanup_uid(callsign, uid)

    return jsonify({'ok': True})


@app.route('/api/uid/remark', methods=['POST'])
def uid_remark():
    """设置某软件 UID 的备注。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    try:
        uid = int(body.get('uid'))
    except (TypeError, ValueError):
        return jsonify({'error': 'uid 无效'}), 400
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    remark = (body.get('remark') or '').strip()[:128]
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE web_identities SET remark=%s WHERE callsign=%s AND uid=%s", (remark or None, callsign, uid))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/stats')
def stats():
    conn = get_conn()
    try:
        cur = conn.cursor()
        d = {}
        for t in ['mqtt_messages', 'voice_frames', 'qso_records', 'telemetry_records']:
            cur.execute(f"SELECT COUNT(*) FROM `{t}`")
            d[t] = cur.fetchone()[0]
        return jsonify(d)
    finally:
        conn.close()


def _parse_emqx_time(s):
    """EMQX connected_at（ISO 8601）→ 本地 naive datetime。"""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _ensure_client_sessions():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS client_sessions (
                uid BIGINT PRIMARY KEY,
                session_start DATETIME(3) NULL,
                last_seen DATETIME(3) NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        conn.commit()
    finally:
        conn.close()


@app.route('/api/online-list')
def online_list():
    """当前在线客户端列表（从 EMQX 客户端 clientid 解析呼号+UID）。
    在线时长按「会话起点」计算：断线 ≤3 分钟视为同一会话连续计算，超过 3 分钟才重新计算。"""
    _ensure_client_sessions()
    now = datetime.now()
    tol = timedelta(minutes=3)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            items = []
            for c in _emqx_clients():
                cid = c.get('clientid', '')
                parts = cid.split('-')
                if len(parts) < 4 or parts[0] != 'FMO':
                    continue
                try:
                    uid = int(parts[-2])
                except ValueError:
                    continue
                emqx_at = _parse_emqx_time(c.get('connected_at')) or now
                cur.execute("SELECT session_start, last_seen FROM client_sessions WHERE uid=%s", (uid,))
                row = cur.fetchone()
                if row and row[1] is not None and (now - row[1]) < tol:
                    ss = row[0]   # 断线 ≤3 分钟 → 延续会话起点
                else:
                    ss = emqx_at   # 新会话 → 用 EMQX 实际连接时间
                cur.execute("INSERT INTO client_sessions (uid, session_start, last_seen) VALUES (%s,%s,%s) "
                            "ON DUPLICATE KEY UPDATE session_start=VALUES(session_start), last_seen=VALUES(last_seen)",
                            (uid, ss, now))
                items.append({'callsign': parts[1], 'uid': uid, 'ip': c.get('ip_address') or '',
                              'connected_at': ss.strftime('%Y-%m-%d %H:%M:%S') if ss else ''})
            conn.commit()
    finally:
        conn.close()
    items.sort(key=lambda x: (x['callsign'], x['uid']))
    return jsonify({'items': items})


@app.route('/api/voice/list')
def voice_list():
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 20))
    callsign = (request.args.get('callsign') or '').strip().upper()
    user = (request.args.get('user') or '').strip().upper()   # 当前登录呼号：只展示其首次登录之后的语音
    KEEP_INDIVIDUAL = 30   # 最新 30 条单独展示，其余按连续同呼号折叠成组（组算 1 条参与分页）
    conn = get_conn()
    try:
        cur = conn.cursor()
        first_login = None
        if user and user != SERVER_INFO['targetCallsign']:
            cur.execute("SELECT created_at FROM web_users WHERE callsign=%s", (user,))
            r = cur.fetchone()
            first_login = r[0] if r and r[0] else None
        where = "callsign IS NOT NULL AND audio IS NOT NULL AND OCTET_LENGTH(audio) > 0"
        params = []
        if first_login:
            where += " AND received_at > %s"
            params.append(first_login)
        if callsign:
            where += " AND callsign LIKE %s"
            params.append(callsign + '%')
        base = "stream_begin_utc, callsign, MAX(uid), COUNT(*), MIN(received_at), MAX(received_at), MAX(compress_mode)"
        cur.execute("SELECT %s FROM voice_frames WHERE %s GROUP BY stream_begin_utc, callsign ORDER BY MIN(received_at) DESC" % (base, where), params)
        rows = cur.fetchall()

        # 构建「展示条目」：最新 KEEP_INDIVIDUAL 条单条，其余按呼号聚合（同一用户所有 31+ 条合成一个组；组不返回子项，展开时另取）
        streams = []
        for sid, cs, uid, cnt, st, et, mode in rows:
            streams.append({'stream_id': sid, 'callsign': cs, 'uid': uid, 'frame_count': cnt,
                            'duration_ms': cnt * (20 if mode == 1 else 80),
                            'start_time': st.strftime('%Y-%m-%d %H:%M:%S') if st else None,
                            'end_time': et.strftime('%Y-%m-%d %H:%M:%S') if et else None})
        display = streams[:KEEP_INDIVIDUAL]
        groups = {}
        for s in streams[KEEP_INDIVIDUAL:]:
            cs = s['callsign']
            if cs in groups:
                g = groups[cs]
                g['group_count'] += 1
                g['total_duration_ms'] += s['duration_ms']
                g['end_time'] = s['end_time']
                g['streams'].append(s)
            else:
                groups[cs] = {'uid': s['uid'], 'group_count': 1, 'total_duration_ms': s['duration_ms'],
                              'start_time': s['start_time'], 'end_time': s['end_time'], 'streams': [s]}
        for cs, g in groups.items():
            if g['group_count'] >= 2:
                display.append({'type': 'group', 'callsign': cs, 'uid': g['uid'],
                                'group_count': g['group_count'], 'total_duration_ms': g['total_duration_ms'],
                                'start_time': g['start_time'], 'end_time': g['end_time']})
            else:
                display.append(g['streams'][0])   # 只有 1 条的仍按单条展示

        start = (page - 1) * size
        page_items = display[start:start + size]
        return jsonify({'items': page_items, 'page': page, 'size': size,
                        'has_more': start + size < len(display)})
    finally:
        conn.close()


@app.route('/api/voice/group-streams')
def voice_group_streams():
    """折叠组展开时取该呼号的语音流列表（字段与 voice/list 一致）。"""
    callsign = (request.args.get('callsign') or '').strip().upper()
    user = (request.args.get('user') or '').strip().upper()
    if not callsign:
        return jsonify({'items': []})
    conn = get_conn()
    try:
        cur = conn.cursor()
        first_login = None
        if user and user != SERVER_INFO['targetCallsign']:
            cur.execute("SELECT created_at FROM web_users WHERE callsign=%s", (user,))
            r = cur.fetchone()
            first_login = r[0] if r and r[0] else None
        where = "callsign=%s AND audio IS NOT NULL AND OCTET_LENGTH(audio) > 0"
        params = [callsign]
        if first_login:
            where += " AND received_at > %s"
            params.append(first_login)
        base = "stream_begin_utc, callsign, MAX(uid), COUNT(*), MIN(received_at), MAX(received_at), MAX(compress_mode)"
        cur.execute("SELECT %s FROM voice_frames WHERE %s GROUP BY stream_begin_utc, callsign ORDER BY MIN(received_at) DESC" % (base, where), params)
        items = []
        for sid, cs, uid, cnt, st, et, mode in cur.fetchall():
            items.append({'stream_id': sid, 'callsign': cs, 'uid': uid, 'frame_count': cnt,
                          'duration_ms': cnt * (20 if mode == 1 else 80),
                          'start_time': st.strftime('%Y-%m-%d %H:%M:%S') if st else None,
                          'end_time': et.strftime('%Y-%m-%d %H:%M:%S') if et else None})
        return jsonify({'items': items})
    finally:
        conn.close()


@app.route('/api/voice/<int:stream_id>/audio.wav')
def voice_audio(stream_id):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT audio, compress_mode FROM voice_frames
            WHERE stream_begin_utc = %s AND audio IS NOT NULL AND OCTET_LENGTH(audio) > 0
            ORDER BY msg_timestamp, frame_index
        """, (stream_id,))
        rows = cur.fetchall()
        if not rows:
            return jsonify({'error': 'no audio'}), 404
        frames = [r[0] for r in rows]
        mode = rows[0][1] or 2
        wav = frames_to_wav(frames, mode)
        if wav is None:
            return jsonify({'error': 'no audio'}), 404
        return Response(wav, mimetype='audio/wav')
    finally:
        conn.close()


_PLAY_HISTORY_SQL = """
CREATE TABLE IF NOT EXISTS web_play_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  callsign VARCHAR(16) NOT NULL,
  stream_id BIGINT NOT NULL,
  played_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_play (callsign, stream_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


@app.route('/api/played', methods=['GET'])
def played_list():
    """返回该呼号的播放历史（跨设备同步）。"""
    callsign = (request.args.get('callsign') or '').strip().upper()
    if not callsign:
        return jsonify({'played': []})
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(_PLAY_HISTORY_SQL)
            cur.execute("SELECT stream_id FROM web_play_history WHERE callsign=%s ORDER BY played_at DESC LIMIT 5000", (callsign,))
            return jsonify({'played': [r[0] for r in cur.fetchall()]})
    finally:
        conn.close()


@app.route('/api/played', methods=['POST'])
def played_mark():
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    try:
        stream_id = int(body.get('stream_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'stream_id 无效'}), 400
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(_PLAY_HISTORY_SQL)
            cur.execute("INSERT IGNORE INTO web_play_history (callsign, stream_id) VALUES (%s, %s)", (callsign, stream_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/played/mark-all', methods=['POST'])
def played_mark_all():
    """把该呼号的全部语音记录标记为已读。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(_PLAY_HISTORY_SQL)
            cur.execute(
                "INSERT IGNORE INTO web_play_history (callsign, stream_id) "
                "SELECT %s, stream_begin_utc FROM voice_frames WHERE audio IS NOT NULL AND OCTET_LENGTH(audio) > 0",
                (callsign,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


AVATAR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'avatars')


@app.route('/api/avatar', methods=['POST'])
def avatar_upload():
    """上传/替换头像：客户端已缩为缩略图（data URL），这里只存缩略图并删旧文件。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    image = (body.get('image') or '').strip()
    if not callsign or not image.startswith('data:image/'):
        return jsonify({'error': '缺少呼号或图片'}), 400
    try:
        meta, b64 = image.split(',', 1)
        fmt = meta.split(';')[0].split('/')[1].lower()
        if fmt == 'jpeg':
            fmt = 'jpg'
        if fmt not in ('png', 'jpg', 'webp', 'gif'):
            return jsonify({'error': '图片格式不支持'}), 400
        data = base64.b64decode(b64)
    except Exception:
        return jsonify({'error': '图片数据无效'}), 400
    if len(data) > 2 * 1024 * 1024:
        return jsonify({'error': '图片过大'}), 400
    os.makedirs(AVATAR_DIR, exist_ok=True)
    filename = 'avatar_%s_%d.%s' % (callsign, int(time.time()), fmt)
    with open(os.path.join(AVATAR_DIR, filename), 'wb') as f:
        f.write(data)
    old = None
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT avatar FROM web_users WHERE callsign=%s", (callsign,))
            r = cur.fetchone()
            old = r[0] if r and r[0] else None
            cur.execute(
                "INSERT INTO web_users (callsign, avatar) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE avatar=VALUES(avatar)", (callsign, filename))
        conn.commit()
    finally:
        conn.close()
    if old and old != filename:
        try:
            os.remove(os.path.join(AVATAR_DIR, old))
        except Exception:
            pass
    return jsonify({'ok': True, 'avatar': filename})


@app.route('/api/avatar/<callsign>')
def avatar_get(callsign):
    callsign = (callsign or '').strip().upper()
    if not callsign:
        return '', 404
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT avatar FROM web_users WHERE callsign=%s", (callsign,))
            r = cur.fetchone()
            filename = r[0] if r and r[0] else None
    finally:
        conn.close()
    if not filename:
        return '', 404
    path = os.path.join(AVATAR_DIR, filename)
    if not os.path.exists(path):
        return '', 404
    resp = send_file(path)
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route('/api/user/<callsign>')
def user_detail(callsign):
    conn = get_conn()
    try:
        cur = conn.cursor()
        info = {'callsign': callsign}
        # 设备信息
        cur.execute("SELECT uid, grid, rig_model, freq_mhz, status FROM rig_status WHERE callsign=%s ORDER BY id DESC LIMIT 1", (callsign,))
        r = cur.fetchone()
        if r:
            info['uid'] = r[0]
            info['grid'] = r[1]
            info['rig_model'] = r[2]
            info['freq_mhz'] = r[3]
            info['status'] = r[4]
        # 服务器描述
        cur.execute("SELECT description FROM server_info_records WHERE callsign=%s AND description IS NOT NULL ORDER BY id DESC LIMIT 1", (callsign,))
        r = cur.fetchone()
        if r:
            info['description'] = r[0]
        # 遥测
        cur.execute("SELECT parsed FROM telemetry_records WHERE callsign=%s AND parsed IS NOT NULL ORDER BY id DESC LIMIT 1", (callsign,))
        r = cur.fetchone()
        if r:
            info['telemetry'] = r[0]
        # 资料
        cur.execute("SELECT parsed FROM control_events WHERE topic LIKE 'FMO/PROFILE%%' AND parsed IS NOT NULL ORDER BY id DESC LIMIT 1")
        r = cur.fetchone()
        if r:
            info['profile'] = r[0]
        # 统计
        cur.execute("SELECT COUNT(DISTINCT stream_begin_utc) FROM voice_frames WHERE callsign=%s", (callsign,))
        info['voice_count'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM qso_records WHERE from_callsign=%s OR to_callsign=%s", (callsign, callsign))
        info['qso_count'] = cur.fetchone()[0]
        cur.execute("SELECT MIN(received_at), MAX(received_at) FROM mqtt_messages WHERE username=%s", (callsign,))
        r = cur.fetchone()
        info['first_seen'] = r[0].strftime('%Y-%m-%d %H:%M:%S') if r and r[0] else None
        info['last_seen'] = r[1].strftime('%Y-%m-%d %H:%M:%S') if r and r[1] else None
        # APRS 数据：分帧取最新（STATION→位置/集群/服务器，STATUS→状态文本），按语音时间；无匹配回退最新
        t = (request.args.get('t') or '').strip()
        try:
            # 位置/集群/服务器（STATION 帧）
            row = None
            if t:
                cur.execute("SELECT ssid, lat, lon, cluster, server_url FROM aprs_records WHERE callsign=%s AND received_at <= %s AND frame_type='STATION' ORDER BY received_at DESC LIMIT 1", (callsign, t))
                row = cur.fetchone()
            if not row:
                cur.execute("SELECT ssid, lat, lon, cluster, server_url FROM aprs_records WHERE callsign=%s AND frame_type='STATION' ORDER BY id DESC LIMIT 1", (callsign,))
                row = cur.fetchone()
            if row:
                info['ssid'] = row[0]
                info['lat'] = row[1]
                info['lon'] = row[2]
                info['cluster'] = row[3]
                info['server_url'] = row[4]
            # 状态文本（STATUS 帧）
            row = None
            if t:
                cur.execute("SELECT status_text FROM aprs_records WHERE callsign=%s AND received_at <= %s AND status_text IS NOT NULL ORDER BY received_at DESC LIMIT 1", (callsign, t))
                row = cur.fetchone()
            if not row:
                cur.execute("SELECT status_text FROM aprs_records WHERE callsign=%s AND status_text IS NOT NULL ORDER BY id DESC LIMIT 1", (callsign,))
                row = cur.fetchone()
            if row:
                info['aprs_status'] = row[0]
        except Exception:
            pass   # aprs_records 表可能还没建
        return jsonify(info)
    finally:
        conn.close()


@app.route('/api/aprs/<callsign>')
def aprs_detail(callsign):
    """某呼号的所有 APRS 数据（按 SSID 分组，可能多台设备）"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        callsign = callsign.upper()
        cur.execute("SELECT DISTINCT COALESCE(ssid, -1) FROM aprs_records WHERE callsign=%s", (callsign,))
        ssids = sorted(r[0] for r in cur.fetchall())
        devices = []
        for sid in ssids:
            d = {'ssid': sid if sid >= 0 else None}
            # 位置/集群/服务器：优先 STATION，无则退到任意有位置的帧
            cur.execute("SELECT lat, lon, cluster, server_url FROM aprs_records WHERE callsign=%s AND COALESCE(ssid,-1)=%s AND frame_type='STATION' ORDER BY id DESC LIMIT 1", (callsign, sid))
            r = cur.fetchone()
            if not r:
                cur.execute("SELECT lat, lon, NULL, NULL FROM aprs_records WHERE callsign=%s AND COALESCE(ssid,-1)=%s AND lat IS NOT NULL ORDER BY id DESC LIMIT 1", (callsign, sid))
                r = cur.fetchone()
            if r:
                d['lat'], d['lon'], d['cluster'], d['server_url'] = r[0], r[1], r[2], r[3]
            # 状态（最新 STATUS）
            cur.execute("SELECT status_text FROM aprs_records WHERE callsign=%s AND COALESCE(ssid,-1)=%s AND status_text IS NOT NULL ORDER BY id DESC LIMIT 1", (callsign, sid))
            r = cur.fetchone()
            if r:
                d['status_text'] = r[0]
            # 天线高度/型号/电台/频率（最新 BEACON）
            cur.execute("SELECT height_m, antenna, rig, freq_mhz FROM aprs_records WHERE callsign=%s AND COALESCE(ssid,-1)=%s AND height_m IS NOT NULL ORDER BY id DESC LIMIT 1", (callsign, sid))
            r = cur.fetchone()
            if r:
                d['height_m'], d['antenna'], d['rig'], d['freq_mhz'] = r[0], r[1], r[2], r[3]
            # 最后活动时间
            cur.execute("SELECT MAX(received_at) FROM aprs_records WHERE callsign=%s AND COALESCE(ssid,-1)=%s", (callsign, sid))
            r = cur.fetchone()
            if r and r[0]:
                d['last_time'] = r[0].strftime('%Y-%m-%d %H:%M:%S')
            devices.append(d)
        return jsonify({'callsign': callsign, 'devices': devices})
    finally:
        conn.close()


@app.route('/')
def index():
    resp = send_file('index.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route('/static/<path:filename>')
def static_file(filename):
    base = os.path.dirname(os.path.abspath(__file__))
    path = os.path.normpath(os.path.join(base, 'static', filename))
    if not path.startswith(os.path.join(base, 'static')):
        return 'Forbidden', 403
    if not os.path.isfile(path):
        return 'Not Found', 404
    # 浏览器支持 gzip 且存在预压缩 .gz（.js 都预压了），直接发 .gz 省带宽（opus 库 1.7MB → ~500KB）
    accept_gzip = 'gzip' in (request.headers.get('Accept-Encoding') or '')
    gz_path = path + '.gz'
    if accept_gzip and os.path.isfile(gz_path):
        resp = send_file(gz_path, mimetype='application/javascript', conditional=False)
        resp.headers['Content-Encoding'] = 'gzip'
        resp.headers['Vary'] = 'Accept-Encoding'
    else:
        resp = send_file(path, conditional=False)
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


# ===== 电台信息（rig 设置）按呼号存服务器 =====
@app.route('/api/rig-profile', methods=['POST'])
def save_rig_profile():
    """保存该呼号的电台信息设置（grid/model/freq/region/height），跨设备统一。"""
    body = request.get_json(force=True, silent=True) or {}
    callsign = (body.get('callsign') or '').strip().upper()
    if not callsign:
        return jsonify({'error': '呼号不能为空'}), 400
    rig = body.get('rig') or {}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS rig_profiles (
                callsign VARCHAR(12) PRIMARY KEY,
                rig_info JSON DEFAULT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='电台信息设置(按呼号)'""")
            cur.execute("INSERT INTO rig_profiles (callsign, rig_info) VALUES (%s,%s) ON DUPLICATE KEY UPDATE rig_info=VALUES(rig_info)",
                        (callsign, json.dumps(rig, ensure_ascii=False)))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True})


@app.route('/api/rig-profile/<callsign>')
def get_rig_profile(callsign):
    callsign = callsign.strip().upper()
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS rig_profiles (
                callsign VARCHAR(12) PRIMARY KEY,
                rig_info JSON DEFAULT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='电台信息设置(按呼号)'""")
            cur.execute("SELECT rig_info FROM rig_profiles WHERE callsign=%s", (callsign,))
            row = cur.fetchone()
        rig = {}
        if row and row[0]:
            try:
                rig = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            except Exception:
                rig = {}
        return jsonify({'callsign': callsign, 'rig': rig})
    finally:
        conn.close()


# ===== 服务器在线/峰值（取 EMQX connections.count / connections.max） =====
@app.route('/api/server-stats')
def server_stats():
    online = peak = None
    try:
        token = _emqx_token()
        req = urllib.request.Request(EMQX_API + '/stats', headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(req, timeout=5) as r:
            arr = json.loads(r.read().decode('utf-8'))
        if arr and isinstance(arr, list) and arr[0]:
            online = arr[0].get('connections.count')
            peak = arr[0].get('connections.max')
    except Exception:
        pass
    return jsonify({'online': online, 'peak': peak})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9529)
