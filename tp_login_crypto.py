#!/usr/bin/env python3
"""
tp_login_crypto.py — Python port of the TL-WR840N login crypto.

This re-implements what the router's own JavaScript (tpEncrypt.js + encrypt.js)
does in the browser before it POSTs a login. It is a faithful reproduction of
legitimate client behaviour against YOUR OWN device — it does not attack
anything. It only turns a (username, password, data) into the encrypted
`data` + `sign` blobs the firmware expects.

What it does NOT do: it does not submit a login. The exact /cgi/login field
names + payload live in lib.js/root.js and should be read next. This keeps the
tool to "reproduce the crypto", not "spray credentials".
"""

import hashlib
import secrets
import base64
import urllib.request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

# ---------------------------------------------------------------------------
# Low-level primitives, each matching one piece of the JS.
# ---------------------------------------------------------------------------

def md5_hex(text: str) -> str:
    """tpEncrypt.js: $.encrypt.MD5 = CryptoJS.MD5(...).toString()"""
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def gen_digits(n: int) -> str:
    """generateRandomIntString(n): n random decimal digits (0-9)."""
    return "".join(str(secrets.randbelow(10)) for _ in range(n))


class AES128CBC:
    """Mirrors $.encrypt.AES: 128-bit key, CBC, PKCS7. Key/IV are the UTF-8
    bytes of 16-digit strings (CryptoJS.enc.Utf8.parse). Output is base64."""
    KEY_LEN = 16   # 128/8
    IV_LEN = 16

    def gen_key(self):
        self.key = gen_digits(self.KEY_LEN)
        self.iv = gen_digits(self.IV_LEN)
        return {"key": self.key, "iv": self.iv}

    def key_string(self) -> str:
        # AES.prototype.getKeyString -> "key=%key%&iv=%iv%"
        return f"key={self.key}&iv={self.iv}"

    def encrypt(self, plaintext: str) -> str:
        padder = sympad.PKCS7(128).padder()
        padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key.encode()), modes.CBC(self.iv.encode()))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return base64.b64encode(ct).decode()   # CryptoJS .toString() == base64


def rsa_encrypt_tplink(plaintext: str, nn_hex: str, ee_hex: str, rsa_bits: int = 512) -> str:
    """Mirrors $.rsa.encrypt(val, nn, ee, 512, flag=1).

    The JS splits the input into blocks of (rsa_bits/8 - 11) = 53 bytes,
    PKCS#1 v1.5-encrypts each block, hex-encodes it, left-pads each block to
    rsa_bits/4 = 128 hex chars, and concatenates. (flag=1 -> PKCS1 padding.)
    """
    n = int(nn_hex, 16)
    e = int(ee_hex, 16)
    pub = RSAPublicNumbers(e, n).public_key()

    str_en_len = rsa_bits // 4          # 128 hex chars per encrypted block
    step = (rsa_bits // 8) - 11         # 53 plaintext bytes per block (PKCS1)

    data = plaintext.encode("utf-8")
    out = ""
    for i in range(0, len(data), step):
        block = data[i:i + step]
        ct = pub.encrypt(block, asympad.PKCS1v15())   # 64 bytes for RSA-512
        h = ct.hex()
        out += h.rjust(str_en_len, "0")               # calculateRsaValue padding
    return out


# ---------------------------------------------------------------------------
# The orchestrator: $.encrypt.encryptor
# ---------------------------------------------------------------------------
class Encryptor:
    def __init__(self):
        self.aes = AES128CBC()

    def set_hash(self, name: str, pwd: str):
        self.hash = md5_hex(name + pwd)

    def set_rsa_key(self, nn_hex: str, ee_hex: str):
        self.nn, self.ee = nn_hex, ee_hex

    def set_seq(self, seq):
        self.seq = int(seq)

    def gen_aes_key(self):
        self.aes.gen_key()
        self.aes_key_string = self.aes.key_string()

    def get_signature(self, seq: int, is_login: bool) -> str:
        if is_login:
            s = f"{self.aes_key_string}&h={self.hash}&s={seq}"
        else:
            s = f"h={self.hash}&s={seq}"
        return rsa_encrypt_tplink(s, self.nn, self.ee)

    def aes_encrypt(self, data: str, is_login: bool = True) -> dict:
        enc_data = self.aes.encrypt(data)
        sign = self.get_signature(self.seq + len(enc_data), is_login)
        return {"data": enc_data, "sign": sign}


# ---------------------------------------------------------------------------
# Helper: fetch the server's public key + seq (the benign pre-auth read).
# ---------------------------------------------------------------------------
def fetch_parm(ip: str) -> dict:
    req = urllib.request.Request(
        f"http://{ip}/cgi/getParm", data=b"",  # POST
        headers={"Referer": f"http://{ip}/", "User-Agent": "Mozilla/5.0"},
    )
    body = urllib.request.urlopen(req, timeout=5).read().decode()
    out = {}
    for line in body.splitlines():
        line = line.strip()
        for key in ("ee", "nn", "seq"):
            if line.startswith(f'var {key}='):
                out[key] = line.split('"')[1]
    return out


if __name__ == "__main__":
    IP = "192.168.0.104"

    # 1) read the server's RSA public key + seq (pre-auth, benign)
    parm = fetch_parm(IP)
    print(f"[*] ee  = {parm['ee']}")
    print(f"[*] nn  = {parm['nn'][:32]}... ({len(parm['nn'])*4} bits)")
    print(f"[*] seq = {parm['seq']}")

    # 2) build the encryptor exactly as the browser would
    enc = Encryptor()
    enc.set_hash("admin", "admin")          # demo creds — nothing is submitted
    enc.set_rsa_key(parm["nn"], parm["ee"])
    enc.set_seq(parm["seq"])
    enc.gen_aes_key()

    # 3) produce the blobs the firmware expects (we just print them)
    result = enc.aes_encrypt("demo-payload", is_login=True)
    print("-" * 70)
    print(f"[*] AES key string : {enc.aes_key_string}")
    print(f"[*] cred hash (MD5): {enc.hash}")
    print(f"[*] data (AES b64) : {result['data']}")
    print(f"[*] sign (RSA hex) : {result['sign'][:64]}... ({len(result['sign'])} hex chars)")
    print("-" * 70)
    print("[note] This reproduces the browser's encryption only. Nothing was")
    print("       sent to /cgi/login. Wiring that up needs the submit code in")
    print("       lib.js / root.js — read those next.")
