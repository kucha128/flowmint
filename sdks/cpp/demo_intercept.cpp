// FlowMint C++ 拦截改包 DEMO（自包含、可直接运行）。
//
// 自己起一个本地源站（返回 500 + 原始 Body），用 FlowMint 在途改包：
//   请求：注入头 X-FlowMint: hello
//   响应：状态码 500 -> 200，Body 换成改写内容
// 再作为客户端走代理请求，校验拿到的是改写后的 200。无需外网、无需 MITM。
//
// 编译（MSVC，x64 Native Tools 命令行）：
//   cl /std:c++17 /EHsc /utf-8 demo_intercept.cpp ^
//      /I ..\..\crates\ffi\include ^
//      /link ..\..\target\release\flowmint.dll.lib ws2_32.lib
// 运行前确保 flowmint.dll 在同目录或 PATH 中。

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>

#include "flowmint.h"

#pragma comment(lib, "ws2_32.lib")

// 绑定一个随机可用端口的监听 socket，返回端口号。
static SOCKET listen_any(uint16_t& port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bind(s, (sockaddr*)&addr, sizeof(addr));
    listen(s, 8);
    int len = sizeof(addr);
    getsockname(s, (sockaddr*)&addr, &len);
    port = ntohs(addr.sin_port);
    return s;
}

// 极简源站：每个连接读完请求头，回 500 + 固定 Body，然后关闭。
static void origin_server(SOCKET srv, bool* running) {
    while (*running) {
        SOCKET c = accept(srv, nullptr, nullptr);
        if (c == INVALID_SOCKET) break;
        char buf[4096];
        recv(c, buf, sizeof(buf), 0);  // 读一坨请求（够读到头即可）
        const char* body = "ORIGINAL BODY FROM SERVER";
        char resp[256];
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(body), body);
        send(c, resp, n, 0);
        closesocket(c);
    }
}

// 拦截回调：改请求头 + 改响应状态/Body。
static int32_t on_intercept(FmInterceptMsg* m, void* /*user*/) {
    if (fm_intercept_is_response(m)) {
        printf("[intercept/resp] status %d -> 200, rewrite body\n", fm_intercept_status(m));
        fm_intercept_set_status(m, 200);
        const char* nb = "BODY REWRITTEN BY FLOWMINT";
        fm_intercept_set_body(m, (const uint8_t*)nb, strlen(nb));
        return 1;  // 修改并放行
    } else {
        printf("[intercept/req ] %s %s -> inject X-FlowMint\n",
               fm_intercept_method(m), fm_intercept_url(m));
        fm_intercept_set_header(m, "X-FlowMint", "hello");
        return 1;
    }
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // 1) 源站
    uint16_t origin_port = 0;
    SOCKET srv = listen_any(origin_port);
    bool running = true;
    std::thread origin(origin_server, srv, &running);

    // 2) FlowMint 代理 + 拦截改包
    const uint16_t proxy_port = 18899;
    FmContext* ctx = fm_context_new();
    fm_bind_port(ctx, proxy_port);
    fm_set_intercept_callback(ctx, on_intercept, nullptr);
    if (!fm_start(ctx)) {
        printf("启动失败: %s\n", fm_last_error(ctx));
        return 2;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 3) 走代理请求源站（绝对形式）
    SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in pa{};
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pa.sin_port = htons(proxy_port);
    connect(cli, (sockaddr*)&pa, sizeof(pa));

    char req[256];
    int rn = snprintf(req, sizeof(req),
        "GET http://127.0.0.1:%u/hello HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
        "Connection: close\r\n\r\n", origin_port, origin_port);
    send(cli, req, rn, 0);

    std::string resp;
    char rb[2048];
    int got;
    while ((got = recv(cli, rb, sizeof(rb), 0)) > 0) resp.append(rb, got);
    closesocket(cli);

    // 4) 校验
    bool ok200 = resp.rfind("HTTP/1.1 200", 0) == 0;
    bool okbody = resp.find("BODY REWRITTEN BY FLOWMINT") != std::string::npos;
    printf("\n==== 客户端最终收到 ====\n%s\n", resp.c_str());
    printf("改包%s\n", (ok200 && okbody) ? "成功 [OK]" : "未生效 [FAIL]");

    // 清理
    fm_stop(ctx);
    fm_context_free(ctx);
    running = false;
    closesocket(srv);
    origin.detach();
    WSACleanup();
    return (ok200 && okbody) ? 0 : 1;
}
