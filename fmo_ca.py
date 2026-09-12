# -*- coding: utf-8 -*-
"""
FMO 自建 CA：rootCA / intermediateCA / userCert 生成与签名。

严格对齐 SAS 源码（BG5ESN/fmo-server-authrozier-service）：
  - src/certs/RootCaCert.cs       rootCA  TBS = 15 元素数组
  - src/certs/IntermediateCaCert.cs  intermediateCA TBS = 20 元素数组
  - src/certs/UserCert.cs         userCert TBS = 9 元素数组
  - 签名 = Ed25519( TBS 的确定性 CBOR 编码 )
  - 证书为 JSON，二进制字段 base64url 无 padding

依赖：cryptography（Ed25519），标准库。
"""
import os
import json
import time
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ---------- base64url ----------

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def b64url_decode(s):
    s = s.strip()
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------- 确定性 CBOR（与 .NET System.Formats.Cbor 输出一致） ----------

def _cbor_uint(v):
    """非负整数：主类型 0，最短长度"""
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
    b = s.encode('utf-8')
    n = len(b)
    if n < 24:
        return bytes([0x60 | n]) + b
    if n < 256:
        return bytes([0x78, n]) + b
    return bytes([0x79]) + n.to_bytes(2, 'big') + b


def _cbor_bytes(b):
    n = len(b)
    if n < 24:
        return bytes([0x40 | n]) + b
    if n < 256:
        return bytes([0x58, n]) + b
    return bytes([0x59]) + n.to_bytes(2, 'big') + b


def _cbor_bool(v):
    return b'\xf5' if v else b'\xf4'


def _cbor_array(n):
    if n < 24:
        return bytes([0x80 | n])
    if n < 256:
        return bytes([0x98, n])
    raise ValueError('array too large')


def _cbor_text_array(items):
    out = _cbor_array(len(items))
    for it in items:
        out += _cbor_text(it)
    return out


# ---------- Ed25519 ----------

def new_keypair():
    """返回 (seed_32B, public_32B)。私钥就是 32 字节 seed。"""
    seed = os.urandom(32)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed, pk


def sign(seed_bytes, data):
    sk = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    return sk.sign(data)


def verify(pk_bytes, data, sig_bytes):
    pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    pk.verify(sig_bytes, data)  # 失败抛 InvalidSignature


# ---------- TBS（签名输入） ----------

def root_tbs(sn, issuer_name, issuer_email, subject_name, subject_pk,
             pathlen, crl, license_, keyid, iat, exp):
    arr = _cbor_array(15)
    arr += _cbor_text('FMO') + _cbor_uint(4) + _cbor_text('rootCA')
    arr += _cbor_uint(sn)
    arr += _cbor_text(issuer_name) + _cbor_text(issuer_email) + _cbor_text(subject_name)
    arr += _cbor_bytes(subject_pk)
    arr += _cbor_bool(True)          # IsCA
    arr += _cbor_uint(pathlen)       # 1
    arr += _cbor_text(crl) + _cbor_text(license_) + _cbor_text(keyid)
    arr += _cbor_uint(iat) + _cbor_uint(exp)
    return arr


def intermediate_tbs(sn, issuer_sn, issuer_name, issuer_pk,
                     subject_name, subject_email, subject_pk, pathlen,
                     keyid, crl, license_, uid_start, uid_end, countries,
                     iat, exp):
    arr = _cbor_array(20)
    arr += _cbor_text('FMO') + _cbor_uint(4) + _cbor_text('intermediateCA')
    arr += _cbor_uint(sn) + _cbor_uint(issuer_sn)
    arr += _cbor_text(issuer_name) + _cbor_bytes(issuer_pk)
    arr += _cbor_text(subject_name) + _cbor_text(subject_email) + _cbor_bytes(subject_pk)
    arr += _cbor_bool(True)          # IsCA
    arr += _cbor_uint(pathlen)       # 0
    arr += _cbor_text(keyid) + _cbor_text(crl) + _cbor_text(license_)
    arr += _cbor_uint(uid_start) + _cbor_uint(uid_end)
    arr += _cbor_text_array(sorted(countries))
    arr += _cbor_uint(iat) + _cbor_uint(exp)
    return arr


def user_tbs(issuer_sn, callsign, uid, public_key, iat, exp):
    arr = _cbor_array(9)
    arr += _cbor_text('FMO') + _cbor_uint(4) + _cbor_text('userCert')
    arr += _cbor_uint(issuer_sn)
    arr += _cbor_text(callsign.upper())
    arr += _cbor_uint(uid)
    arr += _cbor_bytes(public_key)
    arr += _cbor_uint(iat) + _cbor_uint(exp)
    return arr


# ---------- 证书构造 ----------

def build_root(sn, name, email, pathlen, crl, license_, keyid, iat, exp):
    """生成自签名 rootCA。返回 (cert_dict, seed_32B)。"""
    seed, pk = new_keypair()
    tbs = root_tbs(sn, name, email, name, pk, pathlen, crl, license_, keyid, iat, exp)
    sig = sign(seed, tbs)
    cert = {
        'sn': sn,
        'type': 'rootCA',
        'issuer': {'name': name, 'email': email},
        'subject': {'name': name, 'publicKey': b64url_encode(pk)},
        'extensions': {
            'isCA': True,
            'pathLen': pathlen,
            'crl': crl,
            'license': license_,
            'keyId': keyid,
        },
        'iat': iat,
        'exp': exp,
        'signatureAlgorithm': 'Ed25519',
        'signature': b64url_encode(sig),
    }
    return cert, seed


def build_intermediate(root_cert, root_seed, sn, name, email, keyid, crl,
                       license_, uid_start, uid_end, countries, iat, exp):
    """用 root 私钥签发 intermediateCA。返回 (cert_dict, seed_32B)。"""
    seed, pk = new_keypair()
    tbs = intermediate_tbs(
        sn,
        root_cert['sn'],
        root_cert['subject']['name'],
        b64url_decode(root_cert['subject']['publicKey']),
        name, email, pk, 0, keyid, crl, license_,
        uid_start, uid_end, countries, iat, exp,
    )
    sig = sign(root_seed, tbs)
    cert = {
        'sn': sn,
        'type': 'intermediateCA',
        'issuer': {
            'sn': root_cert['sn'],
            'name': root_cert['subject']['name'],
            'publicKey': root_cert['subject']['publicKey'],
        },
        'subject': {'name': name, 'email': email, 'publicKey': b64url_encode(pk)},
        'extensions': {
            'isCA': True,
            'pathLen': 0,
            'keyId': keyid,
            'crl': crl,
            'license': license_,
            'uidRange': {'start': uid_start, 'end': uid_end},
            'issuingCountries': sorted(countries),
        },
        'iat': iat,
        'exp': exp,
        'signatureAlgorithm': 'Ed25519',
        'signature': b64url_encode(sig),
    }
    return cert, seed


def build_user(intermediate_cert, intermediate_seed, callsign, uid,
               client_public_key, iat, exp):
    """用 intermediate 私钥给「客户端公钥」签发 userCert。
    client_public_key 是 32 字节；客户端自己保留私钥。"""
    tbs = user_tbs(intermediate_cert['sn'], callsign.upper(), uid,
                   client_public_key, iat, exp)
    sig = sign(intermediate_seed, tbs)
    cert = {
        'type': 'userCert',
        'issuerSn': intermediate_cert['sn'],
        'subject': {
            'callsign': callsign.upper(),
            'uid': uid,
            'publicKey': b64url_encode(client_public_key),
        },
        'iat': iat,
        'exp': exp,
        'signatureAlgorithm': 'Ed25519',
        'signature': b64url_encode(sig),
    }
    return cert


def fingerprint(cert):
    """证书指纹 = base64url(SHA-256(TBS))，对应 CertBase.Fingerprint()。"""
    kind = cert.get('type')
    if kind == 'rootCA':
        tbs = root_tbs(
            cert['sn'], cert['issuer']['name'], cert['issuer']['email'],
            cert['subject']['name'], b64url_decode(cert['subject']['publicKey']),
            1, cert['extensions']['crl'], cert['extensions']['license'],
            cert['extensions']['keyId'], cert['iat'], cert['exp'],
        )
    elif kind == 'intermediateCA':
        ext = cert['extensions']
        tbs = intermediate_tbs(
            cert['sn'], cert['issuer']['sn'], cert['issuer']['name'],
            b64url_decode(cert['issuer']['publicKey']),
            cert['subject']['name'], cert['subject']['email'],
            b64url_decode(cert['subject']['publicKey']), 0,
            ext['keyId'], ext['crl'], ext['license'],
            ext['uidRange']['start'], ext['uidRange']['end'],
            ext['issuingCountries'], cert['iat'], cert['exp'],
        )
    else:  # userCert
        tbs = user_tbs(
            cert['issuerSn'], cert['subject']['callsign'], cert['subject']['uid'],
            b64url_decode(cert['subject']['publicKey']), cert['iat'], cert['exp'],
        )
    return b64url_encode(hashlib.sha256(tbs).digest())


# ---------- SAS HTTP 鉴权 payload / proof（对应 HttpProofVerifier + HttpPasswordPayload） ----------

def user_fingerprint_raw(user_cert):
    """userCert 指纹的 32 字节原始值（SHA-256(TBS)），用于 proof TBS。"""
    tbs = user_tbs(user_cert['issuerSn'], user_cert['subject']['callsign'],
                   user_cert['subject']['uid'],
                   b64url_decode(user_cert['subject']['publicKey']),
                   user_cert['iat'], user_cert['exp'])
    return hashlib.sha256(tbs).digest()


def proof_tbs(server_uid, target_callsign, target_uid, role, target_url,
              target_port, server_fp_bytes, timestamp, user_fp_bytes):
    """12 元素数组：["FMO",4,"serverAuthorizerReqHttp",...]，被用户私钥签名。"""
    arr = _cbor_array(12)
    arr += _cbor_text('FMO') + _cbor_uint(4) + _cbor_text('serverAuthorizerReqHttp')
    arr += _cbor_uint(server_uid)
    arr += _cbor_text(target_callsign.upper())
    arr += _cbor_uint(target_uid)
    arr += _cbor_text(role)
    arr += _cbor_text(target_url)
    arr += _cbor_uint(target_port)
    arr += _cbor_bytes(server_fp_bytes)
    arr += _cbor_uint(timestamp)
    arr += _cbor_bytes(user_fp_bytes)
    return arr


def build_password(intermediate_cert, user_cert, user_seed, server_uid,
                   target_callsign, target_uid, role, target_url, target_port,
                   server_fingerprint_str, timestamp=None):
    """构造 MQTT CONNECT 的 password = base64url(JSON)，含 proof 签名。"""
    timestamp = timestamp if timestamp is not None else int(time.time())
    server_fp = b64url_decode(server_fingerprint_str)
    user_fp = user_fingerprint_raw(user_cert)
    tbs = proof_tbs(server_uid, target_callsign, target_uid, role, target_url,
                    target_port, server_fp, timestamp, user_fp)
    sig = sign(user_seed, tbs)
    payload = {
        'certPackage': {'intermediateCert': intermediate_cert, 'userCert': user_cert},
        'targetCallsign': target_callsign,
        'targetUID': target_uid,
        'role': role,
        'targetUrl': target_url,
        'targetPort': target_port,
        'serverFingerprint': server_fingerprint_str,
        'timestamp': timestamp,
        'proof': {'signature': b64url_encode(sig)},
    }
    return b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))


# ---------- 链自检（复刻 SAS CertVerifier.VerifyFullChain） ----------

def verify_chain(root, intermediate, user, now=None):
    now = now if now is not None else int(time.time())

    verify(b64url_decode(root['subject']['publicKey']),
           root_tbs(root['sn'], root['issuer']['name'], root['issuer']['email'],
                    root['subject']['name'],
                    b64url_decode(root['subject']['publicKey']), 1,
                    root['extensions']['crl'], root['extensions']['license'],
                    root['extensions']['keyId'], root['iat'], root['exp']),
           b64url_decode(root['signature']))
    assert now < intermediate['exp'], 'intermediate expired'
    ext = intermediate['extensions']
    assert ext['uidRange']['start'] <= ext['uidRange']['end'], 'uidRange reversed'
    verify(b64url_decode(root['subject']['publicKey']),
           intermediate_tbs(intermediate['sn'], intermediate['issuer']['sn'],
                            intermediate['issuer']['name'],
                            b64url_decode(intermediate['issuer']['publicKey']),
                            intermediate['subject']['name'],
                            intermediate['subject']['email'],
                            b64url_decode(intermediate['subject']['publicKey']), 0,
                            ext['keyId'], ext['crl'], ext['license'],
                            ext['uidRange']['start'], ext['uidRange']['end'],
                            ext['issuingCountries'], intermediate['iat'],
                            intermediate['exp']),
           b64url_decode(intermediate['signature']))
    assert now < user['exp'], 'user expired'
    uid = user['subject']['uid']
    assert ext['uidRange']['start'] <= uid <= ext['uidRange']['end'], 'uid out of range'
    verify(b64url_decode(intermediate['subject']['publicKey']),
           user_tbs(user['issuerSn'], user['subject']['callsign'], uid,
                    b64url_decode(user['subject']['publicKey']),
                    user['iat'], user['exp']),
           b64url_decode(user['signature']))
    return True


# ---------- 一次性生成 rootCA + intermediateCA ----------

def generate_ca(out_dir, root_sn=9001, intermediate_sn=9002,
                name='FMO-WEB-CLIENT', email='webclient@fmo.local'):
    now = int(time.time())
    root_iat = now
    root_exp = now + 10 * 365 * 24 * 3600          # 10 年
    inter_iat = now
    inter_exp = now + 5 * 365 * 24 * 3600          # 5 年

    crl = os.environ.get('FMO_CA_CRL', '')
    license_ = os.environ.get('FMO_CA_LICENSE', '')

    root, root_seed = build_root(
        root_sn, name, email, 1, crl, license_, 'web-root', root_iat, root_exp)

    inter, inter_seed = build_intermediate(
        root, root_seed, intermediate_sn, name + '-INTERMEDIATE', email,
        'web-intermediate', crl, license_,
        5000, 99999, ['CN'], inter_iat, inter_exp)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'root-ca.json'), 'w', encoding='utf-8') as f:
        json.dump(root, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, 'root.key'), 'w', encoding='utf-8') as f:
        f.write(b64url_encode(root_seed) + '\n')
    with open(os.path.join(out_dir, 'intermediate-ca.json'), 'w', encoding='utf-8') as f:
        json.dump(inter, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, 'intermediate.key'), 'w', encoding='utf-8') as f:
        f.write(b64url_encode(inter_seed) + '\n')
    os.chmod(os.path.join(out_dir, 'root.key'), 0o600)
    os.chmod(os.path.join(out_dir, 'intermediate.key'), 0o600)

    return root, inter


if __name__ == '__main__':
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else '/www/wwwroot/fmo_api/ca'
    r, i = generate_ca(out)

    # 自检：生成一个测试 userCert 并验链
    now = int(time.time())
    seed, pk = new_keypair()
    u = build_user(i, b64url_decode(
        open(os.path.join(out, 'intermediate.key')).read().strip()),
        'TEST0', 0xF0000001, pk, now, now + 2 * 365 * 24 * 3600)
    verify_chain(r, i, u)

    print('root sn=%d fp=%s' % (r['sn'], fingerprint(r)))
    print('intermediate sn=%d fp=%s uidRange=[%d,%d]' % (
        i['sn'], fingerprint(i), i['extensions']['uidRange']['start'],
        i['extensions']['uidRange']['end']))
    print('test userCert callsign=%s uid=%d fp=%s' % (
        u['subject']['callsign'], u['subject']['uid'], fingerprint(u)))
    print('CHAIN_VERIFY_OK  ->  written to %s' % out)
