"""假 SSH 服务：只发 OpenSSH_7.4 banner，不发 KEXINIT，用于资产验真演示。"""
from __future__ import annotations

import argparse
import socket
import threading
import time

BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"


def handle(c: socket.socket):
    try:
        c.settimeout(3)
        c.sendall(BANNER)
        try:
            c.recv(4096)          # 收下客户端版本与 KEXINIT
        except socket.timeout:
            pass
        time.sleep(2)             # 故意不回应，保持“无握手”
    except OSError:
        pass
    finally:
        c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2222)
    a = ap.parse_args()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.host, a.port))
    s.listen(20)
    print(f"fake ssh on {a.host}:{a.port}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
