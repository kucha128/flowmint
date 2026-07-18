/* FlowMint 纯 C 示例（回调式嵌入）：绑定 HTTP 观察回调、启动抓包代理、打印流量。
 *
 * 编译（MSVC，需先 vcvars64）：
 *   cl /nologo /utf-8 /TC example.c /I ..\..\crates\ffi\include ^
 *      /link ..\..\target\release\flowmint.dll.lib
 * 运行前把 flowmint.dll 放到 example.exe 同目录（或 PATH）。
 *
 * 拦截改包见 flowmint.h 里的 fm_set_intercept_callback / fm_intercept_set_*，
 * 完整改包示例见 sdks/cpp/demo_intercept.cpp（C ABI 相同，C 里用法一致）。
 */
#include <stdio.h>
#include <windows.h>
#include "flowmint.h"

/* HTTP 事件回调（在工作线程触发）。 */
static void on_http(const FmHttpEvent* ev, void* user) {
    (void)user;
    if (fm_http_event_type(ev) == 0) {
        printf("[请求] %s %s\n", fm_http_event_method(ev), fm_http_event_url(ev));
    } else {
        size_t len = 0;
        fm_http_event_body(ev, &len);
        printf("[响应] %d %s (%llu 字节)\n", fm_http_event_status(ev),
               fm_http_event_url(ev), (unsigned long long)len);
    }
    fflush(stdout);
}

int main(void) {
    FmContext* ctx = fm_context_new();
    fm_bind_port(ctx, 8894);
    fm_set_http_callback(ctx, on_http, NULL);

    if (!fm_start(ctx)) {
        printf("启动失败: %s\n", fm_last_error(ctx));
        fm_context_free(ctx);
        return 1;
    }
    printf("FlowMint 纯 C 示例：代理已启动 127.0.0.1:8894（版本 %s）\n", fm_version());
    printf("让客户端走该代理，例如: curl -x http://127.0.0.1:8894 http://目标/\n");
    fflush(stdout);

    Sleep(20000); /* 等外部请求（演示用） */

    fm_stop(ctx);
    fm_context_free(ctx);
    return 0;
}
