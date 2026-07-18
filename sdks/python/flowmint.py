"""FlowMint Python SDK —— C ABI 核心（flowmint 动态库）的薄绑定。

用法（回调式嵌入）：

    import flowmint

    def on_http(ev: flowmint.HttpEvent):
        if ev.is_request:
            print("请求", ev.method, ev.url)
        else:
            print("响应", ev.status, ev.url, len(ev.body), "字节")

    fm = flowmint.FlowMint()
    fm.bind_port(8888)
    fm.on_http(on_http)
    fm.start()            # 让客户端走 127.0.0.1:8888 代理
    ...
    fm.stop()

回调在工作线程触发。事件字段仅在回调期间有效，SDK 已在回调内拷贝为 Python 对象。
"""

from __future__ import annotations

import ctypes as C
import os
from typing import Callable, Optional

REQUEST = 0
RESPONSE = 1

# 拦截动作码（on_intercept 回调的返回值）
CONTINUE = 0  # 放行
MODIFY = 1    # 修改并放行（配合 set_body/set_status/set_header）
DROP = 2      # 丢弃


def _find_dll() -> str:
    """定位 flowmint 动态库：环境变量 > 同目录 > 仓库 target 目录。"""
    name = {"nt": "flowmint.dll", "posix": "libflowmint.so"}.get(os.name, "libflowmint.so")
    env = os.environ.get("FLOWMINT_DLL")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    for cand in (
        os.path.join(here, name),
        os.path.join(root, "target", "release", name),
        os.path.join(root, "target", "debug", name),
    ):
        if os.path.exists(cand):
            return cand
    raise FileNotFoundError(f"找不到 {name}；设置环境变量 FLOWMINT_DLL 指向它")


def _bind(dll_path: str) -> C.CDLL:
    lib = C.CDLL(dll_path)
    p = C.c_void_p
    lib.fm_context_new.restype = p
    lib.fm_context_free.argtypes = [p]
    lib.fm_bind_port.argtypes = [p, C.c_uint16]
    lib.fm_set_mitm.argtypes = [p, C.c_bool, C.c_bool]
    lib.fm_set_ca.argtypes = [p, C.c_char_p, C.c_char_p]
    lib.fm_install_ca.argtypes = [p]
    lib.fm_install_ca.restype = C.c_bool
    lib.fm_set_http_callback.argtypes = [p, _CB, p]
    lib.fm_start.argtypes = [p]
    lib.fm_start.restype = C.c_bool
    lib.fm_stop.argtypes = [p]
    lib.fm_last_error.argtypes = [p]
    lib.fm_last_error.restype = C.c_char_p
    lib.fm_export_ca.argtypes = [p, C.c_char_p]
    lib.fm_export_ca.restype = C.c_bool
    lib.fm_version.restype = C.c_char_p
    lib.fm_http_event_type.argtypes = [p]
    lib.fm_http_event_type.restype = C.c_int32
    for g in ("fm_http_event_method", "fm_http_event_url", "fm_http_event_host"):
        getattr(lib, g).argtypes = [p]
        getattr(lib, g).restype = C.c_char_p
    lib.fm_http_event_status.argtypes = [p]
    lib.fm_http_event_status.restype = C.c_int32
    lib.fm_http_event_body.argtypes = [p, C.POINTER(C.c_size_t)]
    lib.fm_http_event_body.restype = C.POINTER(C.c_ubyte)
    # 拦截改包
    lib.fm_set_intercept_callback.argtypes = [p, _ICB, p]
    lib.fm_intercept_is_response.argtypes = [p]
    lib.fm_intercept_is_response.restype = C.c_int32
    for g in ("fm_intercept_method", "fm_intercept_url"):
        getattr(lib, g).argtypes = [p]
        getattr(lib, g).restype = C.c_char_p
    lib.fm_intercept_status.argtypes = [p]
    lib.fm_intercept_status.restype = C.c_int32
    lib.fm_intercept_body.argtypes = [p, C.POINTER(C.c_size_t)]
    lib.fm_intercept_body.restype = C.POINTER(C.c_ubyte)
    lib.fm_intercept_set_body.argtypes = [p, C.POINTER(C.c_ubyte), C.c_size_t]
    lib.fm_intercept_set_status.argtypes = [p, C.c_int32]
    lib.fm_intercept_set_header.argtypes = [p, C.c_char_p, C.c_char_p]
    return lib


# C 回调签名：void (*)(const FmHttpEvent*, void*)
_CB = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p)
# 拦截回调签名：int32 (*)(FmInterceptMsg*, void*)
_ICB = C.CFUNCTYPE(C.c_int32, C.c_void_p, C.c_void_p)


class HttpEvent:
    """一次 HTTP 事件的快照（回调期间从 C 侧拷贝而来）。"""

    def __init__(self, type_: int, method: str, url: str, host: str, status: int, body: bytes):
        self.type = type_
        self.method = method
        self.url = url
        self.host = host
        self.status = status
        self.body = body

    @property
    def is_request(self) -> bool:
        return self.type == REQUEST

    @property
    def is_response(self) -> bool:
        return self.type == RESPONSE


class Intercept:
    """一条在途消息（拦截回调内使用）：读字段，用 set_* 改写，回调返回动作码。"""

    def __init__(self, lib, ptr):
        self._lib = lib
        self._ptr = ptr
        self.is_response = bool(lib.fm_intercept_is_response(ptr))
        self.method = _cstr(lib.fm_intercept_method(ptr))
        self.url = _cstr(lib.fm_intercept_url(ptr))
        self.status = lib.fm_intercept_status(ptr)
        self.body = _ibody(lib, ptr)

    @property
    def is_request(self) -> bool:
        return not self.is_response

    def set_body(self, data: bytes) -> None:
        buf = (C.c_ubyte * len(data)).from_buffer_copy(data) if data else None
        self._lib.fm_intercept_set_body(self._ptr, buf, len(data))

    def set_status(self, status: int) -> None:
        self._lib.fm_intercept_set_status(self._ptr, status)

    def set_header(self, name: str, value: str) -> None:
        self._lib.fm_intercept_set_header(self._ptr, name.encode(), value.encode())


class FlowMint:
    def __init__(self, dll_path: Optional[str] = None):
        self._lib = _bind(dll_path or _find_dll())
        self._ctx = self._lib.fm_context_new()
        self._cb_holder = None  # 持有 ctypes 回调，防止被 GC
        self._icb_holder = None  # 拦截回调（同上）

    def version(self) -> str:
        return self._lib.fm_version().decode()

    def bind_port(self, port: int) -> "FlowMint":
        self._lib.fm_bind_port(self._ctx, port)
        return self

    def set_mitm(self, enabled: bool, insecure_upstream: bool = False) -> "FlowMint":
        self._lib.fm_set_mitm(self._ctx, enabled, insecure_upstream)
        return self

    def set_ca(self, cert_pem: Optional[str], key_pem: Optional[str]) -> "FlowMint":
        """设置 MITM CA（内存 PEM，不落地）。传 None 则用软件内置默认 CA。"""
        self._lib.fm_set_ca(
            self._ctx,
            cert_pem.encode() if cert_pem else None,
            key_pem.encode() if key_pem else None,
        )
        return self

    def install_ca(self) -> bool:
        """把当前生效的 CA 安装到当前用户根存储（Windows）。"""
        return bool(self._lib.fm_install_ca(self._ctx))

    def on_http(self, callback: Callable[[HttpEvent], None]) -> "FlowMint":
        lib = self._lib

        def trampoline(ev_ptr, _user):
            event = HttpEvent(
                lib.fm_http_event_type(ev_ptr),
                _cstr(lib.fm_http_event_method(ev_ptr)),
                _cstr(lib.fm_http_event_url(ev_ptr)),
                _cstr(lib.fm_http_event_host(ev_ptr)),
                lib.fm_http_event_status(ev_ptr),
                _body(lib, ev_ptr),
            )
            callback(event)

        self._cb_holder = _CB(trampoline)
        lib.fm_set_http_callback(self._ctx, self._cb_holder, None)
        return self

    def on_intercept(self, callback: Callable[["Intercept"], Optional[int]]) -> "FlowMint":
        """注册拦截改包回调。回调收到 Intercept，返回 CONTINUE/MODIFY/DROP
        （返回 None 视为 CONTINUE）。改写用 msg.set_body/set_status/set_header。"""
        lib = self._lib

        def trampoline(msg_ptr, _user):
            action = callback(Intercept(lib, msg_ptr))
            return int(action) if action is not None else CONTINUE

        self._icb_holder = _ICB(trampoline)
        lib.fm_set_intercept_callback(self._ctx, self._icb_holder, None)
        return self

    def export_ca(self, out_path: str) -> bool:
        return bool(self._lib.fm_export_ca(self._ctx, out_path.encode()))

    def start(self) -> None:
        if not self._lib.fm_start(self._ctx):
            raise RuntimeError(self.last_error())

    def stop(self) -> None:
        self._lib.fm_stop(self._ctx)

    def last_error(self) -> str:
        return _cstr(self._lib.fm_last_error(self._ctx))

    def close(self) -> None:
        if self._ctx:
            self._lib.fm_context_free(self._ctx)
            self._ctx = None

    def __enter__(self) -> "FlowMint":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _cstr(p) -> str:
    return p.decode() if p else ""


def _body(lib, ev_ptr) -> bytes:
    n = C.c_size_t(0)
    ptr = lib.fm_http_event_body(ev_ptr, C.byref(n))
    if not ptr or n.value == 0:
        return b""
    return bytes(ptr[: n.value])


def _ibody(lib, msg_ptr) -> bytes:
    n = C.c_size_t(0)
    ptr = lib.fm_intercept_body(msg_ptr, C.byref(n))
    if not ptr or n.value == 0:
        return b""
    return bytes(ptr[: n.value])
