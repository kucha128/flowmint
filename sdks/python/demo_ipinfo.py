"""FlowMint Python demo：把 https://ipinfo.io/json 响应里的 ip 字段改成 12.34.56.78。

流程（全用 SDK 接口，Windows）：
  1. 启动代理（开 MITM，用内置默认证书）并设置拦截回调（改 ip）。
  2. 检查默认证书是否已安装；未安装则调用 SDK 安装到本机受信任根存储。
  3. 把系统代理指向 FlowMint。
  4. 提示用户用浏览器访问 https://ipinfo.io/json，会看到 ip 被改成 12.34.56.78。
  5. 用户按任意键后关闭系统代理并退出。

运行（需先 cargo build -p flowmint-ffi --release 生成 flowmint.dll）：
    python demo_ipinfo.py
"""

from __future__ import annotations

import json
import sys

import flowmint

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

FAKE_IP = "12.34.56.78"
PROXY_PORT = 18890


def on_intercept(m: flowmint.Intercept) -> int:
    # 只改 ipinfo.io 的 /json 响应（MITM 的 url 形如 https://ipinfo.io:443/json）。
    # body 由 SDK 层按 Content-Encoding 解压后给到这里，改包侧直接当明文处理即可。
    if m.is_response and "ipinfo.io" in m.url and m.url.endswith("/json"):
        try:
            data = json.loads(m.body.decode("utf-8"))
        except Exception:
            return flowmint.CONTINUE
        old = data.get("ip")
        data["ip"] = FAKE_IP
        m.set_body(json.dumps(data).encode("utf-8"))
        print(f"[改包] ip {old} -> {FAKE_IP}")
        return flowmint.MODIFY
    return flowmint.CONTINUE


def press_any_key(prompt: str) -> None:
    print(prompt, end="", flush=True)
    try:
        import msvcrt

        msvcrt.getch()
    except ImportError:
        input()
    print()


def main() -> None:
    fm = flowmint.FlowMint()
    # 1) 启动 + 设置回调
    fm.bind_port(PROXY_PORT).set_mitm(True).on_intercept(on_intercept)
    fm.start()

    # 2) 证书：未安装则安装默认证书
    if fm.is_ca_installed():
        print("默认证书已安装。")
    elif fm.install_ca():
        print("已安装默认证书到本机受信任根存储。")
    else:
        print("安装证书失败：", fm.last_error())
        fm.stop()
        fm.close()
        return

    # 3) 设置系统代理
    if not fm.set_system_proxy(PROXY_PORT):
        print("设置系统代理失败：", fm.last_error())

    try:
        print(f"\n系统代理已指向 FlowMint（127.0.0.1:{PROXY_PORT}）。测试任选其一：")
        print(f"  · 浏览器无痕窗口访问  https://ipinfo.io/json  ——ip 应显示为 {FAKE_IP}")
        print(f"  · 或命令行：curl -x 127.0.0.1:{PROXY_PORT} https://ipinfo.io/json --ssl-no-revoke")
        print("  （浏览器若仍看到真实 ip，多半走了 HTTP/3(QUIC) 绕过代理；用 curl 或在浏览器里禁用 QUIC）")
        press_any_key("\n按任意键关闭代理并退出...")
    finally:
        # 4) 关闭系统代理并停止
        fm.clear_system_proxy()
        fm.stop()
        fm.close()
        print("已关闭系统代理，退出。")


if __name__ == "__main__":
    main()
