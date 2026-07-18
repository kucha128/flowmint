# 多语言 SDK 开发

FlowMint 的多语言 SDK 采用**单一 Rust C-ABI 核心 + 各语言薄绑定**：抓包/规则逻辑只在
Rust 里实现一份（`crates/ffi` 编成动态库 `flowmint`），各语言通过同一套 C 接口调用。
这样避免在每种语言里重复实现、也不会与引擎语义漂移。

## 架构

```text
各语言薄绑定 (Python/C++/C#/Java/Go/易语言…)
        │  调用 C ABI
        ▼
crates/ffi  →  flowmint.dll / .so   （唯一实现）
        │
        ▼
proxy-http + tls + model   （抓包引擎）
```

- C 接口定义见 [crates/ffi/include/flowmint.h](../crates/ffi/include/flowmint.h)。
- 动态库产物：`target/{debug,release}/flowmint.dll`（Windows）。构建见 [构建与运行](构建与运行.md)。
- 各语言绑定定位动态库的顺序：环境变量 `FLOWMINT_DLL` > 应用目录/`PATH` > 仓库 `target/*`。

## C ABI 一览

| 函数 | 作用 |
|---|---|
| `fm_context_new` / `fm_context_free` | 创建/释放实例 |
| `fm_bind_port(ctx, port)` | 监听端口（loopback） |
| `fm_set_mitm(ctx, mitm, insecure_upstream)` | 开启 HTTPS 拦截 |
| `fm_set_ca(ctx, cert_pem, key_pem)` | 设 MITM 证书（**内存 PEM，不落地**）；传 NULL/空用内置默认 CA |
| `fm_set_upstream_proxy(ctx, host_port)` | 上游代理链（出站再转发）；传 NULL/空直连 |
| `fm_install_ca(ctx)` → bool | 安装当前 CA 到用户根存储（Windows） |
| `fm_is_ca_installed(ctx)` → bool | 当前 CA 是否已装（Windows） |
| `fm_set_system_proxy(ctx, port)` / `fm_clear_system_proxy(ctx)` → bool | 设置/关闭系统代理（Windows） |
| `fm_set_http_callback(ctx, cb, user)` | 注册 HTTP **观察**回调（只读） |
| `fm_set_intercept_callback(ctx, cb, user)` | 注册**拦截改包**回调（在途可改写） |
| `fm_start(ctx)` / `fm_stop(ctx)` | 启停抓包 |
| `fm_last_error(ctx)` | 取错误信息 |
| `fm_export_ca(ctx, path)` | 导出当前生效的 CA(PEM) |
| `fm_http_event_type/method/url/host/status/body(ev)` | 观察回调内读取事件字段 |
| `fm_intercept_is_response/method/url/status/body(msg)` | 拦截回调内读取消息字段 |
| `fm_intercept_set_body/status/header(msg, …)` | 拦截回调内改写 Body/状态码/头 |
| `fm_set_ws_callback(ctx, cb, user)` | 注册 **WebSocket 帧拦截**回调 |
| `fm_ws_is_outgoing/opcode/payload(frame)` | WS 回调内读方向/opcode/payload |
| `fm_ws_set_payload(frame, …)` | WS 回调内改写帧 payload |

两类回调：
- **观察**（`fm_set_http_callback`）：请求/响应完成后回传，只读。
- **拦截改包**（`fm_set_intercept_callback`）：请求转发前、响应回传前**在途**触发；回调返回
  动作码（`0`=放行 / `1`=修改并放行 / `2`=丢弃），`1` 时配合 `fm_intercept_set_*` 改写。

## 各语言状态

| 语言 | 绑定文件 | 改包 | 本机验证 | 说明 |
|---|---|---|---|---|
| Python | [flowmint.py](../sdks/python/flowmint.py) | ✅ | ✅ 改包 demo 端到端通过 | ctypes，无需编译 |
| C++ | [cpp/example.cpp](../sdks/cpp/example.cpp) | ✅ | ✅ MSVC 编译运行、改包 demo 通过 | 直接包含 `flowmint.h` |
| C | [c/example.c](../sdks/c/example.c) | ✅ | ✅ MSVC 编译通过 | 纯 C，同一头文件 |
| C# | [csharp/FlowMint.cs](../sdks/csharp/FlowMint.cs) | ✅ | ⚠️ 未验证 | P/Invoke；本机只有 .NET 运行时无 SDK |
| Go | [go/flowmint.go](../sdks/go/flowmint.go) | ✅ | ⚠️ 未验证 | cgo；本机无 Go 工具链 |
| Java | [java/FlowMint.java](../sdks/java/FlowMint.java) | ✅ | ⚠️ 未重验 | FFM（java.lang.foreign），纯 Java |
| 易语言 | [e/flowmint.e.txt](../sdks/e/flowmint.e.txt) | ✅ | ⚠️ 未验证 | “DLL 命令”声明；本机无易语言编译器 |
| Android | 复用 Java 绑定 | ✅ | ⚠️ 需交叉编译 | 见下方 Android 小节 |

## 用法片段

**Python**
```python
import flowmint
fm = flowmint.FlowMint()
fm.bind_port(8888).on_http(lambda ev: print(ev.method, ev.url, ev.status)).start()
```

**C/C++**（回调式嵌入）
```cpp
FmContext* ctx = fm_context_new();
fm_bind_port(ctx, 8888);
fm_set_http_callback(ctx, on_http, NULL);
fm_start(ctx);
```

**C#**
```csharp
using var fm = new FlowMint.FlowMint();
fm.BindPort(8888).OnHttp(ev => Console.WriteLine($"{ev.Method} {ev.Url} {ev.Status}")).Start();
```

**Java**
```java
try (var fm = new flowmint.FlowMint()) {
    fm.bindPort((short) 8888);
    fm.onHttp(ev -> System.out.println(ev.method + " " + ev.url + " " + ev.status));
    fm.start();
}
```

**Go**
```go
fm := flowmint.New(); defer fm.Close()
fm.BindPort(8888)
fm.OnHttp(func(ev *flowmint.HttpEvent) { fmt.Println(ev.Method, ev.URL, ev.Status) })
fm.Start()
```

## 拦截改包（在途修改请求/响应）

注册拦截回调，在请求转发前 / 响应回传前改写 Body、状态码、头，或直接丢弃。
**无需 MITM 也能对明文 HTTP 改包**；改 HTTPS 则先开 `fm_set_mitm` 并装证书。

> **Body 压缩由 SDK 层透明处理**：回调拿到的 Body 已按 `Content-Encoding`（gzip/br/deflate/zstd）
> **解压成明文**，直接当明文读写即可；一旦改写，SDK 会按原 `Content-Encoding`**重新压缩、保留该头**
> （未改写的流量原样转发；未知编码则退化为明文并去掉该头）。所以改 JSON/文本响应时**不用自己解压/压缩**。

可直接运行的完整 DEMO（自带本地源站 + 客户端，无需外网）：

- **Python**：[sdks/python/demo_intercept.py](../sdks/python/demo_intercept.py)
  `python demo_intercept.py`（需先 `cargo build -p flowmint-ffi --release`）。
- **C++**：[sdks/cpp/demo_intercept.cpp](../sdks/cpp/demo_intercept.cpp)（文件头有 MSVC 编译命令）。

两个 demo 都演示：请求注入头 `X-FlowMint`，响应 `500 → 200` 且改写 Body，并校验客户端收到改写结果。

**Python 改包片段**
```python
def on_intercept(m: flowmint.Intercept) -> int:
    if m.is_response:
        m.set_status(200)
        m.set_body(b"REWRITTEN")
        return flowmint.MODIFY      # 1
    m.set_header("X-FlowMint", "hello")
    return flowmint.MODIFY

fm.bind_port(8888).on_intercept(on_intercept).start()
```

**C++ 改包片段**
```cpp
int32_t on_intercept(FmInterceptMsg* m, void*) {
    if (fm_intercept_is_response(m)) {
        fm_intercept_set_status(m, 200);
        const char* b = "REWRITTEN";
        fm_intercept_set_body(m, (const uint8_t*)b, strlen(b));
    } else {
        fm_intercept_set_header(m, "X-FlowMint", "hello");
    }
    return 1;  // 修改并放行
}
fm_set_intercept_callback(ctx, on_intercept, nullptr);
```

C# 用 `OnIntercept(m => { …; return InterceptAction.Modify; })`，Go 用 `OnIntercept(func(m *Intercept) int32 { …; return Modify })`，Java 用 `onIntercept(m -> { …; return MODIFY; })`，易语言见声明文件——语义一致。

## 拦截 WebSocket 帧（改帧 / 丢帧 / 主动断开）

ws/wss 抓包默认就有（帧被记录）。**wss 走 MITM 解密**：开 `fm_set_mitm` 并装证书后，wss 的每一帧
会被解密后逐帧抓取/拦截（与 ws 明文完全一致，回调拿到的是明文 payload）。要**改帧/丢帧/断开**，
注册 WS 帧回调 `fm_set_ws_callback`：回调收到每一帧（方向 / opcode / **已解压明文 payload**），返回
`WS_FORWARD`(0) / `WS_MODIFY`(1，配合 `set_payload`) / `WS_DROP`(2，丢弃该帧) / `WS_CLOSE`(3，**主动断开连接**)。

可直接运行的 DEMO（自带本地 ws echo + 客户端）：[sdks/python/demo_ws.py](../sdks/python/demo_ws.py)
（`python demo_ws.py`，演示把文本帧内容改写）。

**Python WS 改帧片段**
```python
def on_ws(f: flowmint.WsFrame) -> int:
    if f.outgoing and f.is_text:       # 客户端发出的文本帧
        f.set_payload(b"HACKED")
        return flowmint.WS_MODIFY
    return flowmint.WS_FORWARD          # 或 WS_DROP 丢帧 / WS_CLOSE 断开

fm.bind_port(8888).on_ws(on_ws).start()
```

## MITM 证书

- `fm_set_mitm(ctx, true, ...)` 开启 HTTPS 解密。证书三选一：
  1. **不设**（`fm_set_ca` 传 NULL/不调用）→ 用**软件内置默认 CA**，开箱即用。
  2. **传自己的证书**：`fm_set_ca(ctx, cert_pem, key_pem)`，**内存 PEM、不落地**（要私有证书时用）。
  3. 需要时 `fm_install_ca(ctx)` 把当前 CA 装进当前用户根存储（Windows），或 `fm_export_ca` 导出自行安装。
- 不开 MITM 只抓明文 HTTP / 隧道元数据，不涉及证书。改包对明文 HTTP 也不需要证书。

## 易语言绑定

完整的「DLL 命令」声明（含观察与拦截改包全部函数）+ 用法示例见
[sdks/e/flowmint.e.txt](../sdks/e/flowmint.e.txt)。要点：

- 指针一律用**长整数型**（整数型），把 `flowmint.dll` 放到程序目录。
- 观察回调子程序：两个**长整数型**参数、无返回值；拦截回调子程序：两个长整数型参数、**返回整数型**（0/1/2）。
  用“取子程序指针”得到地址传给 `fm_set_http_callback` / `fm_set_intercept_callback`。
- 返回文本的命令（`fm_*_url`/`fm_last_error`/`fm_version` 等）返回的是 char* 指针，用“指针到文本”按 UTF-8 转换；
  Body 指针配合 out_len 用“指针到字节集”读取。

## Android

Android 复用 Java 绑定，但需要为目标 ABI 交叉编译动态库：

1. 用 `cargo` 交叉编译 `flowmint` 到 Android 目标（如 `aarch64-linux-android`），产出
   `libflowmint.so`，随 APK 打包到 `jniLibs/<abi>/`。
2. Java 侧：Android 上 `java.lang.foreign`（FFM）可用性依赖 API level；旧版本可改用 JNI/JNA
   加载同一 `.so`。C ABI 保持不变。

> Android 的完整交叉编译与打包尚未在本项目内落地，属后续工作。

## 后续阶段

- TCP / UDP 回调（WebSocket 帧回调已实现，ws/wss 均已验证）。
- 为 C#/Go/易语言/Android 补充可运行的示例与打包脚本（当前 C#/Go/Java/易语言绑定已含改包接口，但未在本机逐一编译验证）。
- 拦截回调内改写请求/响应头的更细粒度控制（删除头、按连接设置上游代理等）。
