#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMO 指纹采集 + 代理端点（EMQX 认证后端）

作用：EMQX 把 MQTT CONNECT 的 {username, password} 转给本端点，
      本端点解码 password（base64url 的 JSON，含 certPackage），
      算出设备证书指纹，然后把请求原样转发给 SAS 做真正鉴权，
      SAS 响应原样返回给 EMQX（代理模式）。

      只有当 SAS 返回 allow 时，才把 (呼号, UID, 指纹) 落库，
      作为「真实设备连接记录」，供后续「呼号 + UID + 证书指纹」三元组验证。

指纹公式（对应 SAS 源码 UserCert.ToTbsCbor() + CertBase.Fingerprint()）：
    fingerprint = base64url( SHA-256( CBOR(["FMO",4,"userCert",
                          issuerSn, callsign, uid, publicKey(32B), iat, exp]) ) )
"""
import json
import os
import base64
import hashlib
import urllib.request
import urllib.error

import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

# SAS 鉴权地址（代理转发目标；容器内默认走 fmo 网络的 sas 服务）
SAS_URL = os.environ.get('FMO_SAS_URL', 'http://sas:8080/auth')

# MySQL（配置从环境变量读取，敏感信息不硬编码进源码）
DB = dict(
    host=os.environ.get('FMO_MYSQL_HOST', '127.0.0.1'),
    port=int(os.environ.get('FMO_MYSQL_PORT', '3306')),
    user=os.environ.get('FMO_MYSQL_USER', 'fmo'),
    password=os.environ.get('FMO_MYSQL_PASSWORD', ''),
    database=os.environ.get('FMO_MYSQL_DB', 'fmo'),
    charset='utf8mb4',
)


# ---------- 确定性 CBOR 编码（与 .NET System.Formats.Cbor 输出一致） ----------

def _cbor_uint(v):
    """非负整数：CBOR 主类型 0，最短长度"""
    if v < 24:
        return bytes([v])
    if v < 256:
        return bytes([0x18, v])
    if v < 65536:
        return bytes([0x19]) + v.to_bytes(2, 'big')
    if v < 4294967296:
        return bytes([0x1A]) + v.to_bytes(4, 'big')
    return bytes([0x1B]) + v.to_bytes(8, 'big')


def _cbor_text(s):
    """文本字符串：CBOR 主类型 3"""
    b = s.encode('utf-8')
    n = len(b)
    if n < 24:
        return bytes([0x60 | n]) + b
    if n < 256:
        return bytes([0x78, n]) + b
    return bytes([0x79]) + n.to_bytes(2, 'big') + b


def _cbor_bytes(b):
    """字节串：CBOR 主类型 2"""
    n = len(b)
    if n < 24:
        return bytes([0x40 | n]) + b
    if n < 256:
        return bytes([0x58, n]) + b
    return bytes([0x59]) + n.to_bytes(2, 'big') + b


def _b64url_decode(s):
    s = s.strip()
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def user_cert_tbs_cbor(cert):
    """按 SAS UserCert.ToTbsCbor() 构造 9 元素数组的确定性 CBOR。

    cert 是 userCert JSON 对象，字段见 UserCert.FromJson：
      issuerSn: long
      subject.callsign: string（发送侧已大写，这里再 .upper() 兜底）
      subject.uid: long
      subject.publicKey: base64url(32 字节)
      iat / exp: long
    """
    issuer_sn = cert['issuerSn']
    callsign = cert['subject']['callsign'].upper()
    uid = cert['subject']['uid']
    public_key = _b64url_decode(cert['subject']['publicKey'])
    iat = cert['iat']
    exp = cert['exp']

    arr = b'\x89'  # array(9)
    arr += _cbor_text('FMO')
    arr += _cbor_uint(4)
    arr += _cbor_text('userCert')
    arr += _cbor_uint(issuer_sn)
    arr += _cbor_text(callsign)
    arr += _cbor_uint(uid)
    arr += _cbor_bytes(public_key)
    arr += _cbor_uint(iat)
    arr += _cbor_uint(exp)
    return arr


def cert_fingerprint(cert):
    """返回设备菜单里显示的 43 字符 base64url 指纹字符串"""
    return _b64url_encode(hashlib.sha256(user_cert_tbs_cbor(cert)).digest())


# ---------- 落库 ----------

_DEVICE_CERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_certs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  callsign VARCHAR(16) NOT NULL,
  uid BIGINT UNSIGNED NOT NULL,
  issuer_sn BIGINT UNSIGNED NOT NULL DEFAULT 0,
  fingerprint CHAR(43) NOT NULL,
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  connect_count INT UNSIGNED NOT NULL DEFAULT 1,
  UNIQUE KEY uk_callsign_uid (callsign, uid),
  KEY idx_fingerprint (fingerprint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def init_db():
    """启动时确保 device_certs 表存在（幂等）。"""
    try:
        conn = pymysql.connect(**DB)
        try:
            with conn.cursor() as cur:
                cur.execute(_DEVICE_CERTS_SCHEMA)
            conn.commit()
        finally:
            conn.close()
        print('[db] device_certs 表已就绪', flush=True)
    except Exception as e:
        print('[db] 建表失败: %r' % (e,), flush=True)


def record_device_cert(callsign, uid, issuer_sn, fingerprint):
    """把真实设备连接记录写入 device_certs 表（按 (呼号, UID) 唯一，upsert）。"""
    try:
        conn = pymysql.connect(**DB)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO device_certs
                        (callsign, uid, issuer_sn, fingerprint,
                         first_seen, last_seen, connect_count)
                    VALUES
                        (%s, %s, %s, %s, NOW(), NOW(), 1)
                    ON DUPLICATE KEY UPDATE
                        fingerprint   = VALUES(fingerprint),
                        issuer_sn     = VALUES(issuer_sn),
                        last_seen     = NOW(),
                        connect_count = connect_count + 1
                    """,
                    (callsign, uid, issuer_sn, fingerprint),
                )
            conn.commit()
        finally:
            conn.close()
        print(json.dumps({'event': 'db_upsert', 'callsign': callsign,
                          'uid': uid, 'fingerprint': fingerprint},
                         ensure_ascii=False), flush=True)
    except Exception as e:
        print('[db] 落库失败: %r' % (e,), flush=True)


# ---------- 采集端点（代理） ----------

@app.route('/capture', methods=['POST'])
def capture():
    raw = request.get_data()
    print('[raw] content-type=%r len=%d hex=%s' % (
        request.headers.get('Content-Type'), len(raw), raw.hex()[:300]), flush=True)
    d = request.get_json(force=True, silent=True) or {}
    print('[parsed] username=%r password_type=%s password_repr=%r' % (
        d.get('username'), type(d.get('password')).__name__, d.get('password')), flush=True)

    # 1. 先解析指纹（不落库，等 SAS 判定 allow 后才落库）
    parsed = None  # {'callsign', 'uid', 'issuerSn', 'fingerprint'} or None
    try:
        password = d.get('password', '')
        payload = json.loads(_b64url_decode(password))
        user_cert = payload['certPackage']['userCert']
        callsign = user_cert['subject']['callsign'].upper()
        uid = user_cert['subject']['uid']
        issuer_sn = user_cert.get('issuerSn', 0)
        fp = cert_fingerprint(user_cert)

        parsed = {'callsign': callsign, 'uid': uid,
                  'issuerSn': issuer_sn, 'fingerprint': fp}
        print(json.dumps({'event': 'capture',
                          'username': d.get('username'),
                          'callsign': callsign, 'uid': uid,
                          'issuerSn': issuer_sn, 'fingerprint': fp},
                         ensure_ascii=False), flush=True)
    except Exception as e:
        print('[capture] 解析失败: %r' % (e,), flush=True)

    # 2. 转发给 SAS 做真正鉴权，并把 SAS 响应原样返回给 EMQX（代理）
    resp_body = None
    resp_status = 200
    resp_mimetype = 'application/json'
    try:
        req = urllib.request.Request(
            SAS_URL,
            data=json.dumps(d).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            resp_body = r.read()
            resp_status = r.status
            resp_mimetype = r.headers.get('Content-Type', 'application/json')
    except urllib.error.HTTPError as e:
        resp_body = e.read()
        resp_status = e.code
        resp_mimetype = 'application/json'
    except Exception as e:
        print('[proxy] 转发 SAS 失败: %r' % (e,), flush=True)
        return jsonify({"result": "deny"})

    # 3. 只有 SAS 判定 allow 的连接才落库（防伪造 package 污染记录）
    if parsed is not None and resp_body:
        try:
            sas_json = json.loads(resp_body.decode('utf-8'))
            if sas_json.get('result') == 'allow':
                record_device_cert(parsed['callsign'], parsed['uid'],
                                   parsed['issuerSn'], parsed['fingerprint'])
            else:
                print('[db] SAS 未放行(result=%r)，跳过落库' %
                      (sas_json.get('result'),), flush=True)
        except Exception as e:
            print('[db] 解析 SAS 响应失败: %r' % (e,), flush=True)

    return app.response_class(resp_body or b'', status=resp_status,
                              mimetype=resp_mimetype)


@app.route('/health', methods=['GET'])
def health():
    return jsonify(ok=True)


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=9530)
