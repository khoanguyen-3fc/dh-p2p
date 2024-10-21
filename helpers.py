"""
DH-P2P Helper Functions
"""
import base64
import datetime
import hashlib
import hmac
import json
import random
import socket
import sys
import time
from struct import pack, unpack

import xmltodict
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAIN_SERVER = "www.easy4ipcloud.com"
MAIN_PORT = 8800

USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
USERKEY = "996103384cdf19179e19243e959bbf8b"
RANDSALT = "5daf91fc5cfc1be8e081cfb08f792726"
IV = b"2z52*lk9o6HRyJrf"

CSEQ = 0


def get_key(username, password):
    key = f"{username}:Login to {RANDSALT}:{password}"
    return hashlib.md5(key.encode()).hexdigest().upper().encode()


def get_nonce():
    return random.randrange(2**31)


def get_enc(key: bytes, nonce: int, data: str):
    salt = str(nonce).encode()
    dk = hashlib.pbkdf2_hmac("sha256", key, salt, 20000, 32)

    encryptor = Cipher(
        algorithms.AES(dk), modes.OFB(IV), backend=default_backend()
    ).encryptor()
    enc = encryptor.update(data.encode()) + encryptor.finalize()

    return base64.b64encode(enc).decode()


def get_dec(key: bytes, nonce: int, data: str):
    salt = str(nonce).encode()
    dk = hashlib.pbkdf2_hmac("sha256", key, salt, 20000, 32)

    encryptor = Cipher(
        algorithms.AES(dk), modes.OFB(IV), backend=default_backend()
    ).encryptor()
    dec = encryptor.update(base64.b64decode(data)) + encryptor.finalize()

    return dec.decode()


def get_auth(username, key, nonce, payload=""):
    curdate = int(time.time())

    message = f"{nonce}{curdate}{payload}".encode()
    auth = base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()).decode()

    return (
        f"<CreateDate>{curdate}</CreateDate>"
        f"<DevAuth>{auth}</DevAuth>"
        f"<Nonce>{nonce}</Nonce>"
        f"<RandSalt>{RANDSALT}</RandSalt>"
        f"<UserName>{username}</UserName>"
    )


class PTCPPayload:
    def __init__(self, realm, payload) -> None:
        self.realm = realm
        self.payload = payload

    def __bytes__(self) -> bytes:
        length = len(self.payload) | 0x10000000
        return pack("!LLL", length, self.realm, 0) + self.payload

    def __str__(self) -> str:
        return f"PTCPPayload(realm={self.realm:08X}, payload={self.payload})"

    @classmethod
    def parse(cls, data: bytes):
        """
        Parse a PTCPPayload from a byte string
        """
        if len(data) < 12:
            raise ValueError("Packet is too short")

        length, realm, pad = unpack("!LLL", data[:12])

        if pad != 0:
            raise ValueError("Invalid padding")

        length &= 0xFFFF
        data = data[12:]

        if len(data) != length:
            raise ValueError("Invalid length")

        return cls(realm, data)


class PTCP:
    def __init__(self, rlid, llid, pid, lmid, rmid, body=b"") -> None:
        self.rlid = rlid
        self.llid = llid
        self.pid = pid
        self.lmid = lmid
        self.rmid = rmid
        self.body = body

    def __bytes__(self) -> bytes:
        return (
            pack(
                "!4sLLLLL",
                b"PTCP",
                self.rlid,
                self.llid,
                self.pid,
                self.lmid,
                self.rmid,
            )
            + self.body
        )

    def __str__(self) -> str:
        return f"PTCP(rlid={self.rlid:08X}, llid={self.llid:08X}, pid={self.pid:08X}, lmid={self.lmid:08X}, rmid={self.rmid:08X}, body={self.body})"

    @classmethod
    def parse(cls, data: bytes):
        """
        Parse a PTCP packet from a byte string
        """
        if len(data) < 24:
            raise ValueError("Packet is too short")

        header, body = data[:24], data[24:]
        magic, rlid, llid, pid, lmid, rmid = unpack("!4sLLLLL", header)

        if magic != b"PTCP":
            raise ValueError("Invalid magic")

        return cls(rlid, llid, pid, lmid, rmid, body)


class UDP(socket.socket):
    def __init__(self, host, port, debug=False):
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM)

        self.bind(("0.0.0.0", 0))

        self.debug = debug

        self.lhost, self.lport = self.getsockname()

        self.rhost = host
        self.rport = port

        self.ptcp_sent = 0
        self.ptcp_recv = 0
        self.ptcp_count = 0
        self.ptcp_id = 0

        self.rmid = 0

    def send(self, data):
        self.sendto(data, (self.rhost, self.rport))

    def recv(self, bufsize=4096, timeout=None):
        if timeout:
            self.settimeout(timeout)

        data = self.recvfrom(bufsize)[0]

        if timeout:
            self.settimeout(None)

        return data

    def read(self, return_error=False):
        data = self.recv().decode()

        print(f":{self.lport} <<< {self.rhost}:{self.rport}")
        print(data.replace("\r\n", "\n"))

        res = parse_response(data)

        if not return_error and res["code"] >= 400:
            print("Error:", res["status"])
            sys.exit(1)

        print("Parsed <<<")
        print(json.dumps(res, indent=2))

        return res

    def request(self, path, body="", auth=True, should_read=True):
        global CSEQ
        CSEQ += 1

        nonce = random.randrange(2**31)
        curdate = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        pwd = f"{nonce}{curdate}DHP2P:{USERNAME}:{USERKEY}"
        hash_digest = hashlib.sha1()
        hash_digest.update(pwd.encode())
        digest = base64.b64encode(hash_digest.digest()).decode()

        req = f"""{'DHPOST' if body else 'DHGET'} {path} HTTP/1.1
CSeq: {CSEQ}
"""
        if auth:
            req += f"""Authorization: WSSE profile="UsernameToken"
X-WSSE: UsernameToken Username="{USERNAME}", PasswordDigest="{digest}", Nonce="{nonce}", Created="{curdate}"
"""

        if body:
            req += f"""Content-Type: 
Content-Length: {len(body)}
"""

        req += f"""
{body}"""

        print(f":{self.lport} >>> {self.rhost}:{self.rport}")
        print(req)
        self.send(req.replace("\n", "\r\n").encode())

        return self.read() if should_read else None

    def read_ptcp(self):
        data = self.recv()

        if self.debug:
            print(f":{self.lport} <<< {self.rhost}:{self.rport}")
            # print(data)

        res = PTCP.parse(data)
        self.ptcp_recv += len(res.body)
        self.rmid = res.lmid

        if self.debug:
            # print("Parsed <<<")
            print(res)

        return res

    def request_ptcp(self, body=b""):
        ptcp = PTCP(
            self.ptcp_sent,
            self.ptcp_recv,
            0x0002FFFF if body == b"\x00\x03\x01\x00" else 0x0000FFFF - self.ptcp_count,
            self.ptcp_id,
            self.rmid,
            body,
        )

        self.ptcp_sent += len(ptcp.body)
        self.ptcp_id += 1
        if len(ptcp.body) > 0 and ptcp.body != b"\x00\x03\x01\x00":
            self.ptcp_count += 1

        if self.debug:
            print(f":{self.lport} >>> {self.rhost}:{self.rport}")
            print(ptcp)
        self.send(bytes(ptcp))


def parse_response(data):
    headers, body = data.split("\r\n\r\n", 1)
    headers = headers.split("\r\n")
    version, code, status = headers[0].split(" ", 2)
    code = int(code)

    return {
        "version": version,
        "code": code,
        "status": status,
        "headers": dict(h.split(": ", 1) for h in headers[1:]),
        "data": xmltodict.parse(body) if body.strip() else None,
    }
