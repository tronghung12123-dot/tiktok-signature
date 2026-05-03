#!/usr/bin/env python3
"""
mobile_signer.py — Python signing bridge cho Node.js
Node.js gọi: python3 mobile_signer.py
Input  (stdin): JSON { "query": "...", "ts": 1234, "device_id": "...", "cookie": "..." }
Output (stdout): JSON { "X-Argus": "...", "X-Ladon": "...", "X-Gorgon": "...", "X-Khronos": "..." }

Đặt file này cùng thư mục với server.js
Cần thư mục signer/ từ https://github.com/tr4cex/TikTok-Encryption
"""

import sys
import json
import os
import hashlib
import struct
import time

# ── Load tr4cex signer nếu có ──────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

SIGNER_AVAILABLE = False
argus_mod = None
ladon_mod = None
gorgon_mod = None

try:
    from signer import argus as argus_mod
    from signer import ladon as ladon_mod
    from signer import gorgon as gorgon_mod
    SIGNER_AVAILABLE = True
except ImportError:
    pass  # Fallback mode


# ── Fallback: X-Gorgon only ───────────────────────────────
def _rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for idx in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[idx] = data[idx] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)


def fallback_gorgon(query: str, ts: int, cookie: str = "") -> dict:
    qh = hashlib.md5(query.encode()).digest() if query else bytes(16)
    bh = bytes(16)
    ch = hashlib.md5(cookie.encode()).digest() if cookie else bytes(16)
    payload = bytearray([0x03, 0x04, 0x01, 0x00])
    payload += struct.pack("<I", ts)
    payload += qh + bh + ch
    xc = 0
    for b in payload:
        xc ^= b
    payload.append(xc)
    key = bytes([0x05, 0x18, 0x07, 0x36, 0x06, 0x2d, 0x41, 0x01,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    enc = _rc4(bytes(payload), key)
    return {
        "X-Gorgon": "0404b0d30000" + enc.hex(),
        "X-Khronos": str(ts),
        "X-Argus": "",
        "X-Ladon": "",
        "signer": "fallback_gorgon_only",
    }


# ── Main signing function ──────────────────────────────────
def sign(query: str, ts: int, device_id: str, cookie: str = "") -> dict:
    if SIGNER_AVAILABLE:
        try:
            # Dùng tr4cex signer (X-Argus + X-Ladon + X-Gorgon + X-Khronos)
            x_argus = argus_mod.generate(query, "", device_id, ts)
            x_ladon = ladon_mod.generate(device_id, ts)
            gorgon_result = gorgon_mod.generate(query, "", cookie, ts)

            return {
                "X-Argus": x_argus,
                "X-Ladon": x_ladon,
                "X-Gorgon": gorgon_result.get("x-gorgon", ""),
                "X-Khronos": gorgon_result.get("x-khronos", str(ts)),
                "signer": "tr4cex_full",
            }
        except Exception as e:
            sys.stderr.write(f"[Signer] tr4cex error: {e}, fallback\n")

    return fallback_gorgon(query, ts, cookie)


# ── Entry point ───────────────────────────────────────────
if __name__ == "__main__":
    try:
        raw = sys.stdin.read().strip()
        data = json.loads(raw)

        query = data.get("query", "")
        ts = int(data.get("ts", time.time()))
        device_id = data.get("device_id", "7629627162782778888")
        cookie = data.get("cookie", "")

        result = sign(query, ts, device_id, cookie)
        print(json.dumps(result))

    except Exception as e:
        # Trả về fallback thay vì crash
        ts = int(time.time())
        sys.stderr.write(f"[Signer] Fatal: {e}\n")
        print(json.dumps({
            "X-Gorgon": "",
            "X-Khronos": str(ts),
            "X-Argus": "",
            "X-Ladon": "",
            "signer": "error",
            "error": str(e),
        }))
