"""FlowMint Python demo：把 https://ipinfo.io/json 响应里的 ip 字段改成 12.34.56.78。

启动 FlowMint 代理（开 MITM，用内置默认证书），拦截 ipinfo.io/json 的响应，改写 JSON 的 ip 字段。
客户端走该代理请求，并信任 FlowMint 导出的 CA，最终收到改写后的 ip。

运行（需能访问 ipinfo.io）：
    python demo_ipinfo.py
（需先 cargo build -p flowmint-ffi --release 生成 flowmint.dll）

若本机需经上游代理才能上网，设环境变量：FLOWMINT_UPSTREAM=127.0.0.1:10809
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import tempfile
import time
import urllib.request

import flowmint

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

FAKE_IP = "12.34.56.78"
PROXY_PORT = 18890
TARGET = "https://ipinfo.io/json"


def on_intercept(m: flowmint.Intercept) -> int:
    # 只改 ipinfo.io 的 /json 响应（MITM 的 url 形如 https://ipinfo.io:443/json）
    if m.is_response and "ipinfo.io" in m.url and m.url.endswith("/json"):
        try:
            data = json.loads(m.body.decode("utf-8"))
        except Exception:
            print("[跳过] 响应不是 JSON（可能被压缩）")
            return flowmint.CONTINUE
        old = data.get("ip")
        data["ip"] = FAKE_IP
        m.set_body(json.dumps(data).encode("utf-8"))
        print(f"[改包] ip {old} -> {FAKE_IP}")
        return flowmint.MODIFY
    return flowmint.CONTINUE


def main() -> None:
    fm = flowmint.FlowMint()
    fm.bind_port(PROXY_PORT).set_mitm(True).on_intercept(on_intercept)
    up = os.environ.get("FLOWMINT_UPSTREAM")
    if up:
        fm.set_upstream_proxy(up)  # 出站经上游代理上网
    fm.start()
    time.sleep(0.3)

    # 导出当前 CA（默认证书），供客户端信任
    ca_path = os.path.join(tempfile.gettempdir(), "flowmint-demo-ca.pem")
    fm.export_ca(ca_path)

    try:
        ctx = ssl.create_default_context(cafile=ca_path)
        proxy = f"http://127.0.0.1:{PROXY_PORT}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
            urllib.request.HTTPSHandler(context=ctx),
        )
        req = urllib.request.Request(
            TARGET,
            headers={"Accept-Encoding": "identity", "User-Agent": "flowmint-demo"},
        )
        with opener.open(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        print("\n==== 客户端最终收到 ====")
        print(json.dumps(body, ensure_ascii=False, indent=2))
        ok = body.get("ip") == FAKE_IP
        print("\n改包" + ("成功 [OK]" if ok else "未生效 [FAIL]"))
        raise SystemExit(0 if ok else 1)
    finally:
        fm.stop()
        fm.close()


if __name__ == "__main__":
    main()
