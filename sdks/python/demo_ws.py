"""FlowMint Python WebSocket 拦截 demo（自包含，可直接运行）。

自己起一个本地 WebSocket echo 服务，用 FlowMint 在途拦截 WS 帧：
  - 把客户端发出的文本帧内容改写（hello world -> HACKED BY FLOWMINT）
回调里还可 return WS_DROP 丢弃该帧、WS_CLOSE 主动断开连接。

运行（需先 cargo build -p flowmint-ffi --release 生成 flowmint.dll）：
    python demo_ws.py
无需外网、无需 MITM（明文 ws 即可演示 WS 改帧）。
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

import flowmint

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

PROXY_PORT = 18896
NEW_TEXT = b"HACKED BY FLOWMINT"


# ---- 极简 WebSocket 帧编解码（够 demo 用）----
def _recvn(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return buf
        buf += c
    return buf


def ws_encode(payload: bytes, mask: bool, opcode: int = 1) -> bytes:
    b = bytearray([0x80 | opcode])
    n = len(payload)
    if mask:
        b.append(0x80 | n)
        m = os.urandom(4)
        b += m
        b += bytes(c ^ m[i % 4] for i, c in enumerate(payload))
    else:
        b.append(n)
        b += payload
    return bytes(b)


def ws_read(s: socket.socket):
    h = _recvn(s, 2)
    if len(h) < 2:
        return None, None
    opcode = h[0] & 0x0F
    masked = h[1] & 0x80
    n = h[1] & 0x7F
    m = _recvn(s, 4) if masked else None
    data = _recvn(s, n) if n else b""
    if masked:
        data = bytes(c ^ m[i % 4] for i, c in enumerate(data))
    return opcode, data


def echo_server(srv: socket.socket) -> None:
    conn, _ = srv.accept()
    head = b""
    while b"\r\n\r\n" not in head:
        d = conn.recv(1024)
        if not d:
            return
        head += d
    conn.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"
    )
    while True:
        op, data = ws_read(conn)
        if op is None or op == 8:  # EOF / close
            break
        conn.sendall(ws_encode(data, mask=False, opcode=op))  # 原样回显


def on_ws(f: flowmint.WsFrame) -> int:
    # 只改客户端发出的文本帧；WS 帧的 payload SDK 已给明文。
    if f.outgoing and f.is_text:
        print(f"[WS 改帧] {f.payload!r} -> {NEW_TEXT!r}")
        f.set_payload(NEW_TEXT)
        return flowmint.WS_MODIFY
    return flowmint.WS_FORWARD
    # 也可：return flowmint.WS_DROP   # 丢弃这一帧
    #        return flowmint.WS_CLOSE  # 主动断开连接


def main() -> None:
    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen()
    echo_port = origin.getsockname()[1]
    threading.Thread(target=echo_server, args=(origin,), daemon=True).start()

    fm = flowmint.FlowMint()
    fm.bind_port(PROXY_PORT).on_ws(on_ws)
    fm.start()
    time.sleep(0.3)

    try:
        cli = socket.socket()
        cli.connect(("127.0.0.1", PROXY_PORT))
        cli.sendall(
            (
                f"GET http://127.0.0.1:{echo_port}/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo_port}\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            head += cli.recv(1)

        cli.sendall(ws_encode(b"hello world", mask=True))
        _, data = ws_read(cli)

        print("\n==== 客户端最终收到 ====")
        print(data.decode(errors="replace"))
        ok = data == NEW_TEXT
        print("\nWS 改帧" + ("成功 [OK]" if ok else "未生效 [FAIL]"))
        raise SystemExit(0 if ok else 1)
    finally:
        fm.stop()
        fm.close()


if __name__ == "__main__":
    main()
