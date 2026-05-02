#!/usr/bin/env python3
"""
TikTok Mobile API Microservice
Dùng signer từ tr4cex/TikTok-Encryption (thư mục signer/)
Port: 8081
"""

import json, os, sys, time, hashlib, gzip, zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

PORT = int(os.environ.get("MOBILE_SERVICE_PORT", 8081))

# Import signer từ thư mục signer/ (tr4cex/TikTok-Encryption)
SIGNER_AVAILABLE = False
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from signer import argus as argus_mod
    from signer import ladon as ladon_mod  
    from signer import gorgon as gorgon_mod
    SIGNER_AVAILABLE = True
    print("[MobileService] Signer loaded OK (tr4cex/TikTok-Encryption)")
except ImportError as e:
    print(f"[MobileService] WARNING: signer/ not found: {e}")
    print("[MobileService] Chạy ở chế độ fallback (X-Gorgon only)")


# ── Fallback X-Gorgon (nếu chưa có signer/) ──────────────
import struct

def _rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for idx in range(len(data)):
        i = (i+1)%256; j=(j+S[i])%256
        S[i],S[j]=S[j],S[i]
        out[idx]=data[idx]^S[(S[i]+S[j])%256]
    return bytes(out)

def fallback_gorgon(query, ts, cookie=""):
    qh = hashlib.md5(query.encode()).digest() if query else bytes(16)
    bh = bytes(16)
    ch = hashlib.md5(cookie.encode()).digest() if cookie else bytes(16)
    payload = bytearray([0x03,0x04,0x01,0x00])
    payload += struct.pack("<I", ts)
    payload += qh + bh + ch
    xc = 0
    for b in payload: xc ^= b
    payload.append(xc)
    key = bytes([0x05,0x18,0x07,0x36,0x06,0x2d,0x41,0x01,0,0,0,0,0,0,0,0])
    enc = _rc4(bytes(payload), key)
    return {"X-Gorgon": "0404b0d30000"+enc.hex(), "X-Khronos": str(ts),
            "X-Argus": "", "X-Ladon": ""}


def sign_request(query, ts, device_id, cookie=""):
    """Ký request — dùng tr4cex signer nếu có, fallback nếu không"""
    if SIGNER_AVAILABLE:
        try:
            xargus = argus_mod.generate(query, "", device_id, ts)
            xladon = ladon_mod.generate(device_id, ts)
            gorgon_data = gorgon_mod.generate(query, "", cookie, ts)
            return {
                "X-Argus": xargus,
                "X-Ladon": xladon,
                "X-Gorgon": gorgon_data.get("x-gorgon", ""),
                "X-Khronos": str(ts),
            }
        except Exception as e:
            print(f"[MobileService] Signer error: {e}, dùng fallback")
    return fallback_gorgon(query, ts, cookie)


# ── Mobile API ────────────────────────────────────────────
MOBILE_UA = (
    "com.zhiliaoapp.musically/2022600030 "
    "(Linux; U; Android 13; vi_VN; SM-G991B; "
    "Build/TP1A.220624.014; Cronet/TTNetVersion:b4d74d15 "
    "2023-04-18 QuicVersion:0144d358 2023-04-09)"
)

BASE_PARAMS = {
    "os_api": "29", "device_type": "SM-G991B", "ssmix": "a",
    "manifest_version_code": "2022600030", "dpi": "420",
    "uoo": "0", "carrier_region": "VN", "region": "VN",
    "app_name": "musical_ly", "version_name": "22.6.0",
    "timezone_offset": "25200", "ab_version": "22.6.0",
    "residence": "VN", "app_type": "normal", "ac2": "wifi", "ac": "wifi",
    "app_version": "22.6.0", "host_abi": "armeabi-v7a",
    "locale": "vi-VN", "aid": "1233", "channel": "googleplay",
    "timezone_name": "Asia/Ho_Chi_Minh",
    "device_platform": "android", "version_code": "220600",
    "sys_region": "VN", "language": "vi", "os_version": "13",
}

DEVICE_ID = "7629627162782778888"


def parse_cookie(s):
    r = {}
    for p in s.split(";"):
        p = p.strip()
        eq = p.find("=")
        if eq == -1: continue
        r[p[:eq].strip()] = p[eq+1:].strip()
    return r


def mobile_request(path, params, session_cookie, method="POST"):
    full_params = {**BASE_PARAMS, "device_id": DEVICE_ID,
                   "cdid": DEVICE_ID, "iid": str(int(DEVICE_ID)+1),
                   **params, "ts": str(int(time.time()))}
    query_str = urlencode(full_params)
    url = f"https://api16-normal-c-useast1a.tiktokv.com{path}?{query_str}"
    ts = int(time.time())
    sig = sign_request(query_str, ts, DEVICE_ID, session_cookie)
    print(f"[MobileService] X-Argus: {sig['X-Argus'][:30] if sig['X-Argus'] else '(empty)'}...")
    headers = {
        "Cookie": session_cookie, "User-Agent": MOBILE_UA,
        "Accept": "application/json", "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Gorgon": sig["X-Gorgon"], "X-Khronos": sig["X-Khronos"],
        "X-Argus": sig["X-Argus"], "X-Ladon": sig["X-Ladon"],
        "sdk-version": "2", "x-vc-bdturing-sdk-version": "2.3.4.i18n",
    }
    req = Request(url, headers=headers, method=method)
    if method == "POST": req.data = b""
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read()
            try: raw = gzip.decompress(raw)
            except: 
                try: raw = zlib.decompress(raw)
                except: pass
            text = raw.decode("utf-8", errors="replace")
            try: return {"status": resp.status, "data": json.loads(text), "raw": text[:300]}
            except: return {"status": resp.status, "data": None, "raw": text[:300]}
    except HTTPError as e:
        raw = e.read()
        try: raw = gzip.decompress(raw)
        except: pass
        text = raw.decode("utf-8", errors="replace")
        return {"status": e.code, "data": None, "raw": text[:300], "error": str(e)}
    except URLError as e:
        return {"status": 0, "data": None, "raw": "", "error": str(e)}


def get_user_info(username, session_cookie):
    result = mobile_request("/aweme/v1/user/",
        {"unique_id": username}, session_cookie, "GET")
    if result.get("data"):
        u = result["data"].get("user", {})
        if u.get("sec_uid"):
            return {"secUid": u["sec_uid"], "userId": u["uid"], "nickname": u.get("nickname","")}
    return None


def follow_user(sec_uid, user_id, session_cookie, action=1):
    return mobile_request("/aweme/v1/commit/follow/user/", {
        "user_id": user_id, "sec_user_id": sec_uid,
        "type": str(action), "from": "21", "from_pre": "11", "channel_id": "0",
    }, session_cookie)


# ── HTTP Handler ──────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[MobileService] {fmt % args}")

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        if not n: return {}
        try: return json.loads(self.rfile.read(n))
        except: return {}

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/mobile/health":
            self.send_json(200, {"status":"ok","signer_available":SIGNER_AVAILABLE,"port":PORT})
        else:
            self.send_json(404, {"error":"Not found"})

    def do_POST(self):
        p = urlparse(self.path).path
        body = self.read_body()

        if p == "/mobile/sign":
            query = body.get("query",""); cookie = body.get("cookie","")
            ts = int(time.time())
            self.send_json(200, sign_request(query, ts, DEVICE_ID, cookie))
            return

        if p == "/mobile/follow":
            cookie = body.get("cookie","")
            username = body.get("username","")
            target_url = body.get("target_url","")
            action = int(body.get("action",1))
            if target_url and not username:
                import re
                m = re.search(r"@([^/?&]+)", target_url)
                if m: username = m.group(1)
            if not cookie or not username:
                self.send_json(400,{"ok":False,"error":"Cần cookie và username"})
                return
            cookie_obj = parse_cookie(cookie)
            sessionid = cookie_obj.get("sessionid","")
            if not sessionid:
                self.send_json(400,{"ok":False,"error":"Không có sessionid trong cookie"})
                return
            session_cookie = f"sessionid={sessionid}; sessionid_ss={sessionid}; sid_tt={sessionid}"
            print(f"[MobileService] Follow @{username}...")
            user_info = get_user_info(username, session_cookie)
            if not user_info:
                self.send_json(500,{"ok":False,"error":f"Không lấy được thông tin @{username}"})
                return
            print(f"[MobileService] userId={user_info['userId']}")
            result = follow_user(user_info["secUid"], user_info["userId"], session_cookie, action)
            print(f"[MobileService] Result: {json.dumps(result)[:200]}")
            tcode = result.get("data",{}).get("status_code") if result.get("data") else None
            success = result.get("status")==200 and tcode in (0,None)
            self.send_json(200,{
                "ok": success,
                "status_code": result.get("status"),
                "tiktok_status_code": tcode,
                "target_username": username,
                "user_info": user_info,
                "data": result.get("data"),
                "raw": result.get("raw","")[:200],
                "signer_used": "tr4cex" if SIGNER_AVAILABLE else "fallback_gorgon_only",
                "message": f"Follow @{username} thành công" if success else
                           f"Lỗi: {tcode} - {result.get('data',{}).get('status_msg','') if result.get('data') else result.get('error','')}"
            })
            return
        self.send_json(404,{"error":"Not found"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[MobileService] Running on port {PORT}")
    print(f"[MobileService] Signer: {'tr4cex/TikTok-Encryption' if SIGNER_AVAILABLE else 'fallback (X-Gorgon only)'}")
    server.serve_forever()
