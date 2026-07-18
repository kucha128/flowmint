"""端到端验证 Python SDK：起本地目标 → 启 FlowMint 代理 → 走代理请求 → 断言回调捕获。"""

import http.server
import socketserver
import threading
import time
import urllib.request

import flowmint


class _Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true,"path":"' + self.path.encode() + b'"}')

    def log_message(self, *a):
        pass


def main() -> None:
    target = socketserver.TCPServer(("127.0.0.1", 9600), _Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    events = []

    def on_http(ev: flowmint.HttpEvent):
        events.append(ev)
        tag = "请求" if ev.is_request else "响应"
        extra = ev.status if ev.is_response else ""
        print(tag, ev.method, ev.url, extra, len(ev.body), "字节")

    fm = flowmint.FlowMint()
    print("SDK 版本:", fm.version())
    fm.bind_port(8891).on_http(on_http).start()
    print("代理已启动 127.0.0.1:8891")

    proxy = urllib.request.ProxyHandler({"http": "http://127.0.0.1:8891"})
    opener = urllib.request.build_opener(proxy)
    r = opener.open("http://127.0.0.1:9600/api/hello", timeout=5)
    print("目标返回:", r.status, r.read().decode())

    time.sleep(0.3)  # 等回调触发
    fm.stop()
    target.shutdown()

    reqs = [e for e in events if e.is_request]
    resps = [e for e in events if e.is_response]
    assert any(e.url.endswith("/api/hello") for e in reqs), "未捕获到请求回调"
    assert any(e.status == 200 for e in resps), "未捕获到响应回调"
    print(f"OK: Python SDK 捕获到 {len(reqs)} 个请求 / {len(resps)} 个响应")


if __name__ == "__main__":
    main()
