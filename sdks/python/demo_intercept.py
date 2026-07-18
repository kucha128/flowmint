"""FlowMint Python 拦截改包 DEMO。

启动一个本地源站（返回固定内容），再用 FlowMint 在途改包：
  - 请求：注入头 X-FlowMint: hello
  - 响应：把 Body 替换成改写内容，并把状态码改成 200

运行：
    python demo_intercept.py
（需要先 `cargo build -p flowmint-ffi --release` 生成 flowmint.dll）

它会自己起源站、起代理、用系统 urllib 走代理请求，打印改包前后的对比——
无需外网、无需 MITM（明文 HTTP 即可演示改包）。
"""

from __future__ import annotations

import http.client
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import flowmint

# Windows 控制台默认 GBK，统一切到 UTF-8 避免中文/符号乱码。
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ---- 1) 本地源站：任何路径都返回一句原始内容 ----
class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ORIGINAL BODY FROM SERVER"
        self.send_response(500)  # 故意返回 500，稍后被改包改成 200
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass  # 静音


def main() -> None:
    origin = HTTPServer(("127.0.0.1", 0), Origin)
    origin_port = origin.server_address[1]
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    proxy_port = 18888

    # ---- 2) FlowMint：注册拦截回调，改请求与响应 ----
    def on_intercept(m: flowmint.Intercept) -> int:
        if m.is_request:
            print(f"[拦截·请求] {m.method} {m.url} → 注入头 X-FlowMint")
            m.set_header("X-FlowMint", "hello")
            return flowmint.MODIFY
        else:
            print(f"[拦截·响应] 原状态 {m.status}, 原 Body={m.body!r} → 改为 200 + 新 Body")
            m.set_status(200)
            m.set_body(b"BODY REWRITTEN BY FLOWMINT")
            return flowmint.MODIFY

    fm = flowmint.FlowMint()
    fm.bind_port(proxy_port).on_intercept(on_intercept)
    fm.start()
    time.sleep(0.3)  # 等代理起来

    try:
        # ---- 3) 走代理请求源站，看改包结果 ----
        # 直接连代理并发送绝对形式请求（避免 urllib 对 localhost 绕过代理）。
        conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
        conn.request("GET", f"http://127.0.0.1:{origin_port}/hello")
        resp = conn.getresponse()
        status = resp.status
        body = resp.read()
        conn.close()

        print("\n==== 客户端最终收到 ====")
        print("状态码:", status, "（源站本是 500，被改成 200）")
        print("Body  :", body.decode(errors="replace"))

        ok = status == 200 and body == b"BODY REWRITTEN BY FLOWMINT"
        print("\n改包" + ("成功 [OK]" if ok else "未生效 [FAIL]"))
        raise SystemExit(0 if ok else 1)
    finally:
        fm.stop()
        fm.close()
        origin.shutdown()


if __name__ == "__main__":
    main()
