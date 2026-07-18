/*
 * FlowMint C ABI —— 各语言 SDK 共用的稳定接口（设计 §11）。
 *
 * 用法（回调式嵌入）：
 *   FmContext* ctx = fm_context_new();
 *   fm_bind_port(ctx, 8888);
 *   fm_set_http_callback(ctx, on_http, NULL);        // 只读观察
 *   fm_set_intercept_callback(ctx, on_intercept, NULL); // 在途改包（可选）
 *   fm_start(ctx);
 *   ... 让客户端走 127.0.0.1:8888 代理 ...
 *   fm_stop(ctx);
 *   fm_context_free(ctx);
 *
 * 回调在工作线程触发；事件/消息指针仅在回调期间有效。
 * 观察回调只读；拦截回调可用 fm_intercept_set_* 改写 Body/状态/头，或返回丢弃。
 */
#ifndef FLOWMINT_H
#define FLOWMINT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FmContext FmContext;
typedef struct FmHttpEvent FmHttpEvent;
typedef struct FmInterceptMsg FmInterceptMsg;

/* HTTP 事件回调。ev 仅在回调期间有效；user 为注册时传入的用户指针。 */
typedef void (*FmHttpCallback)(const FmHttpEvent* ev, void* user);

/* 拦截改包回调。返回动作码：0=放行, 1=修改并放行, 2=丢弃。 */
typedef int32_t (*FmInterceptCallback)(FmInterceptMsg* msg, void* user);

/* ---- 生命周期 ---- */
FmContext*  fm_context_new(void);
void        fm_context_free(FmContext* ctx);
void        fm_bind_port(FmContext* ctx, uint16_t port);
void        fm_set_mitm(FmContext* ctx, bool mitm, bool insecure_upstream);
/* 设置 MITM CA（内存 PEM，不落地）；传 NULL/空则用软件内置默认 CA。fm_start 前调用。 */
void        fm_set_ca(FmContext* ctx, const char* cert_pem, const char* key_pem);
void        fm_set_http_callback(FmContext* ctx, FmHttpCallback cb, void* user);
void        fm_set_intercept_callback(FmContext* ctx, FmInterceptCallback cb, void* user);
bool        fm_start(FmContext* ctx);   /* 失败返回 false，用 fm_last_error 取原因 */
void        fm_stop(FmContext* ctx);
const char* fm_last_error(FmContext* ctx);
bool        fm_export_ca(FmContext* ctx, const char* out_path);  /* 导出当前生效 CA(PEM) */
bool        fm_install_ca(FmContext* ctx);                       /* 安装当前 CA 到用户根存储(Windows) */
const char* fm_version(void);

/* ---- 事件读取（仅回调期间有效）---- */
int32_t     fm_http_event_type(const FmHttpEvent* ev);   /* 0=请求, 1=响应 */
const char* fm_http_event_method(const FmHttpEvent* ev);
const char* fm_http_event_url(const FmHttpEvent* ev);
const char* fm_http_event_host(const FmHttpEvent* ev);
int32_t     fm_http_event_status(const FmHttpEvent* ev); /* 请求为 -1 */
const uint8_t* fm_http_event_body(const FmHttpEvent* ev, size_t* out_len);

/* ---- 拦截改包（仅拦截回调期间有效）---- */
int32_t     fm_intercept_is_response(const FmInterceptMsg* msg); /* 1=响应, 0=请求 */
const char* fm_intercept_method(const FmInterceptMsg* msg);
const char* fm_intercept_url(const FmInterceptMsg* msg);
int32_t     fm_intercept_status(const FmInterceptMsg* msg);      /* 请求为 -1 */
const uint8_t* fm_intercept_body(const FmInterceptMsg* msg, size_t* out_len);
/* 改写（需回调返回 1 才生效）：*/
void        fm_intercept_set_body(FmInterceptMsg* msg, const uint8_t* data, size_t len);
void        fm_intercept_set_status(FmInterceptMsg* msg, int32_t status);
void        fm_intercept_set_header(FmInterceptMsg* msg, const char* name, const char* value);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FLOWMINT_H */
