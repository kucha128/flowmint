// Package flowmint —— FlowMint C ABI 核心（flowmint）的 cgo 薄绑定。
//
// 说明：本机未安装 Go，此文件为代码交付、未在本机编译验证。使用时需保证
// 头文件与动态库可被 cgo 找到（见下方 CFLAGS/LDFLAGS，或自行调整路径），
// 运行时 flowmint.dll / libflowmint.so 在可加载路径中。
//
// 用法（回调式嵌入）：
//
//	fm := flowmint.New()
//	defer fm.Close()
//	fm.BindPort(8888)
//	fm.OnHttp(func(ev *flowmint.HttpEvent) {
//	    fmt.Println(ev.Method, ev.URL, ev.Status)
//	})
//	fm.Start()   // 让客户端走 127.0.0.1:8888 代理
package flowmint

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -L${SRCDIR}/../../target/debug -lflowmint
#include <stdlib.h>
#include "flowmint.h"

// 由 cgo 导出的 Go 回调（下方 //export）。
void fm_go_http_cb(const FmHttpEvent* ev, void* user);
int32_t fm_go_intercept_cb(FmInterceptMsg* msg, void* user);
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"
)

// HttpEvent 是一次 HTTP 事件的快照。
type HttpEvent struct {
	Type   int // 0=请求, 1=响应
	Method string
	URL    string
	Host   string
	Status int // 请求为 -1
	Body   []byte
}

func (e *HttpEvent) IsRequest() bool  { return e.Type == 0 }
func (e *HttpEvent) IsResponse() bool { return e.Type == 1 }

// 拦截动作码（OnIntercept 回调返回值）。
const (
	Continue int32 = 0 // 放行
	Modify   int32 = 1 // 修改并放行
	Drop     int32 = 2 // 丢弃
)

// FlowMint 是一个抓包实例。
type FlowMint struct {
	ctx     *C.FmContext
	handle  cgo.Handle
	ihandle cgo.Handle
}

// New 创建实例。
func New() *FlowMint {
	return &FlowMint{ctx: C.fm_context_new()}
}

func (f *FlowMint) BindPort(port uint16) {
	C.fm_bind_port(f.ctx, C.uint16_t(port))
}

func (f *FlowMint) SetMitm(enabled, insecureUpstream bool) {
	C.fm_set_mitm(f.ctx, C._Bool(enabled), C._Bool(insecureUpstream))
}

func (f *FlowMint) SetDataDir(dir string) {
	c := C.CString(dir)
	defer C.free(unsafe.Pointer(c))
	C.fm_set_data_dir(f.ctx, c)
}

// OnHttp 注册 HTTP 回调（在工作线程触发）。
func (f *FlowMint) OnHttp(fn func(*HttpEvent)) {
	f.handle = cgo.NewHandle(fn)
	C.fm_set_http_callback(f.ctx, C.FmHttpCallback(C.fm_go_http_cb), unsafe.Pointer(f.handle))
}

// OnIntercept 注册拦截改包回调。回调返回 Continue/Modify/Drop；用 msg.Set* 改写。
func (f *FlowMint) OnIntercept(fn func(*Intercept) int32) {
	f.ihandle = cgo.NewHandle(fn)
	C.fm_set_intercept_callback(f.ctx, C.FmInterceptCallback(C.fm_go_intercept_cb), unsafe.Pointer(f.ihandle))
}

// Intercept 是一条在途消息（拦截回调内使用）。
type Intercept struct {
	msg        *C.FmInterceptMsg
	IsResponse bool
	Method     string
	URL        string
	Status     int
	Body       []byte
}

func (m *Intercept) IsRequest() bool { return !m.IsResponse }

// SetBody 改写 Body（需回调返回 Modify）。
func (m *Intercept) SetBody(b []byte) {
	var p *C.uint8_t
	if len(b) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&b[0]))
	}
	C.fm_intercept_set_body(m.msg, p, C.size_t(len(b)))
}

// SetStatus 改写响应状态码（需回调返回 Modify）。
func (m *Intercept) SetStatus(status int) { C.fm_intercept_set_status(m.msg, C.int32_t(status)) }

// SetHeader 设置/替换一个头（需回调返回 Modify）。
func (m *Intercept) SetHeader(name, value string) {
	cn, cv := C.CString(name), C.CString(value)
	defer C.free(unsafe.Pointer(cn))
	defer C.free(unsafe.Pointer(cv))
	C.fm_intercept_set_header(m.msg, cn, cv)
}

func readIntercept(msg *C.FmInterceptMsg) *Intercept {
	var n C.size_t
	bodyPtr := C.fm_intercept_body(msg, &n)
	var body []byte
	if bodyPtr != nil && n > 0 {
		body = C.GoBytes(unsafe.Pointer(bodyPtr), C.int(n))
	}
	return &Intercept{
		msg:        msg,
		IsResponse: C.fm_intercept_is_response(msg) != 0,
		Method:     C.GoString(C.fm_intercept_method(msg)),
		URL:        C.GoString(C.fm_intercept_url(msg)),
		Status:     int(C.fm_intercept_status(msg)),
		Body:       body,
	}
}

//export fm_go_intercept_cb
func fm_go_intercept_cb(msg *C.FmInterceptMsg, user unsafe.Pointer) C.int32_t {
	fn := cgo.Handle(user).Value().(func(*Intercept) int32)
	return C.int32_t(fn(readIntercept(msg)))
}

func (f *FlowMint) Start() error {
	if !bool(C.fm_start(f.ctx)) {
		return errors.New(C.GoString(C.fm_last_error(f.ctx)))
	}
	return nil
}

func (f *FlowMint) Stop() { C.fm_stop(f.ctx) }

func (f *FlowMint) Close() {
	C.fm_context_free(f.ctx)
	if f.handle != 0 {
		f.handle.Delete()
	}
	if f.ihandle != 0 {
		f.ihandle.Delete()
	}
}

func readEvent(ev *C.FmHttpEvent) *HttpEvent {
	var n C.size_t
	bodyPtr := C.fm_http_event_body(ev, &n)
	var body []byte
	if bodyPtr != nil && n > 0 {
		body = C.GoBytes(unsafe.Pointer(bodyPtr), C.int(n))
	}
	return &HttpEvent{
		Type:   int(C.fm_http_event_type(ev)),
		Method: C.GoString(C.fm_http_event_method(ev)),
		URL:    C.GoString(C.fm_http_event_url(ev)),
		Host:   C.GoString(C.fm_http_event_host(ev)),
		Status: int(C.fm_http_event_status(ev)),
		Body:   body,
	}
}

//export fm_go_http_cb
func fm_go_http_cb(ev *C.FmHttpEvent, user unsafe.Pointer) {
	fn := cgo.Handle(user).Value().(func(*HttpEvent))
	fn(readEvent(ev))
}
