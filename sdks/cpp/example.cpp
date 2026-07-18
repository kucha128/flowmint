// FlowMint C/C++ 示例（回调式嵌入）：绑定 HTTP 回调、启动抓包代理、打印流量。
//
// 编译（MSVC，需先 vcvars64）：
//   cl /nologo /utf-8 /EHsc /I ..\..\crates\ffi\include example.cpp ^
//      /link ..\..\target\release\flowmint.dll.lib
// 运行前把 flowmint.dll 放到 example.exe 同目录（或 PATH）。

#include <cstdio>
#include <windows.h>
#include "flowmint.h"

// HTTP 事件回调（在工作线程触发）。
static void on_http(const FmHttpEvent* ev, void* /*user*/) {
    int type = fm_http_event_type(ev);
    const char* url = fm_http_event_url(ev);
    if (type == 0) {
        printf("[请求] %s %s\n", fm_http_event_method(ev), url);
    } else {
        size_t len = 0;
        fm_http_event_body(ev, &len);
        printf("[响应] %d %s (%llu 字节)\n", fm_http_event_status(ev), url,
               (unsigned long long)len);
    }
    fflush(stdout);
}

int main() {
    FmContext* ctx = fm_context_new();
    fm_bind_port(ctx, 8893);
    fm_set_http_callback(ctx, on_http, NULL);

    if (!fm_start(ctx)) {
        printf("启动失败: %s\n", fm_last_error(ctx));
        fm_context_free(ctx);
        return 1;
    }
    printf("FlowMint C++ 示例：代理已启动 127.0.0.1:8893（版本 %s）\n", fm_version());
    printf("让客户端走该代理，例如: curl -x http://127.0.0.1:8893 http://目标/\n");
    fflush(stdout);

    Sleep(20000); // 等外部请求（演示用）

    fm_stop(ctx);
    fm_context_free(ctx);
    return 0;
}
