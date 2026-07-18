// FlowMint Java SDK —— C ABI 核心（flowmint）的 FFM（java.lang.foreign）薄绑定。
// 纯 Java 直接调用动态库，无需 JNI C 胶水。
//
// JDK 21：FFM 为预览特性，编译/运行需 --enable-preview（见 sdks/java/verify.ps1）。
// JDK 22+：FFM 已转正，去掉 --enable-preview 即可（并把 getUtf8String 换成 getString）。
//
// 用法（回调式嵌入）：
//   try (var fm = new FlowMint()) {
//     fm.bindPort((short) 8888);
//     fm.onHttp(ev -> System.out.println(ev.method + " " + ev.url + " " + ev.status));
//     fm.start();
//   }

package flowmint;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

public final class FlowMint implements AutoCloseable {
    public static final class HttpEvent {
        public int type;            // 0=请求, 1=响应
        public String method = "";
        public String url = "";
        public String host = "";
        public int status;          // 请求为 -1
        public byte[] body = new byte[0];
        public boolean isRequest() { return type == 0; }
        public boolean isResponse() { return type == 1; }
    }

    private static final Linker LINKER = Linker.nativeLinker();
    private static final ValueLayout.OfInt I32 = ValueLayout.JAVA_INT;
    private static final ValueLayout.OfShort U16 = ValueLayout.JAVA_SHORT;
    private static final ValueLayout.OfBoolean BOOL = ValueLayout.JAVA_BOOLEAN;

    private final Arena arena = Arena.ofShared();
    private final SymbolLookup lib;
    private final MemorySegment ctx;
    private final MethodHandle hFree, hBindPort, hSetMitm, hSetCa, hInstallCa, hSetCb, hStart, hStop,
            hLastErr, hVersion, hExportCa, hEvType, hEvMethod, hEvUrl, hEvHost, hEvStatus, hEvBody;
    private final MethodHandle hSetICb, hIResp, hIMethod, hIUrl, hIStatus, hIBody,
            hISetBody, hISetStatus, hISetHeader;
    private MemorySegment cbStub;
    private Consumer<HttpEvent> handler;
    private MemorySegment icbStub;
    private java.util.function.ToIntFunction<Intercept> interceptor;

    /** 拦截动作码（onIntercept 回调返回值）。 */
    public static final int CONTINUE = 0, MODIFY = 1, DROP = 2;

    /** 一条在途消息：读字段，用 set* 改写，回调返回动作码。 */
    public final class Intercept {
        private final MemorySegment msg;
        public final boolean isResponse;
        public final String method, url;
        public final int status;
        public final byte[] body;

        Intercept(MemorySegment msg) throws Throwable {
            this.msg = msg;
            this.isResponse = (int) hIResp.invoke(msg) != 0;
            this.method = cstr((MemorySegment) hIMethod.invoke(msg));
            this.url = cstr((MemorySegment) hIUrl.invoke(msg));
            this.status = (int) hIStatus.invoke(msg);
            this.body = readInterceptBody(msg);
        }

        public boolean isRequest() { return !isResponse; }

        public void setBody(byte[] data) throws Throwable {
            MemorySegment buf = data.length == 0 ? MemorySegment.NULL
                    : arena.allocate(data.length).copyFrom(MemorySegment.ofArray(data));
            hISetBody.invoke(msg, buf, (long) data.length);
        }

        public void setStatus(int status) throws Throwable { hISetStatus.invoke(msg, status); }

        public void setHeader(String name, String value) throws Throwable {
            hISetHeader.invoke(msg, arena.allocateUtf8String(name), arena.allocateUtf8String(value));
        }
    }

    public FlowMint() { this(locateDll()); }

    public FlowMint(String dllPath) {
        lib = SymbolLookup.libraryLookup(Path.of(dllPath), arena);
        MethodHandle hNew = dc("fm_context_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
        hFree = dc("fm_context_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        hBindPort = dc("fm_bind_port", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, U16));
        hSetMitm = dc("fm_set_mitm", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, BOOL, BOOL));
        hSetCa = dc("fm_set_ca", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hInstallCa = dc("fm_install_ca", FunctionDescriptor.of(BOOL, ValueLayout.ADDRESS));
        hSetCb = dc("fm_set_http_callback", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hStart = dc("fm_start", FunctionDescriptor.of(BOOL, ValueLayout.ADDRESS));
        hStop = dc("fm_stop", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        hLastErr = dc("fm_last_error", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hVersion = dc("fm_version", FunctionDescriptor.of(ValueLayout.ADDRESS));
        hExportCa = dc("fm_export_ca", FunctionDescriptor.of(BOOL, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hEvType = dc("fm_http_event_type", FunctionDescriptor.of(I32, ValueLayout.ADDRESS));
        hEvMethod = dc("fm_http_event_method", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hEvUrl = dc("fm_http_event_url", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hEvHost = dc("fm_http_event_host", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hEvStatus = dc("fm_http_event_status", FunctionDescriptor.of(I32, ValueLayout.ADDRESS));
        hEvBody = dc("fm_http_event_body", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hSetICb = dc("fm_set_intercept_callback", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hIResp = dc("fm_intercept_is_response", FunctionDescriptor.of(I32, ValueLayout.ADDRESS));
        hIMethod = dc("fm_intercept_method", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hIUrl = dc("fm_intercept_url", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hIStatus = dc("fm_intercept_status", FunctionDescriptor.of(I32, ValueLayout.ADDRESS));
        hIBody = dc("fm_intercept_body", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        hISetBody = dc("fm_intercept_set_body", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        hISetStatus = dc("fm_intercept_set_status", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, I32));
        hISetHeader = dc("fm_intercept_set_header", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        try {
            ctx = (MemorySegment) hNew.invoke();
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private MethodHandle dc(String name, FunctionDescriptor fd) {
        return LINKER.downcallHandle(lib.find(name).orElseThrow(() -> new RuntimeException("缺少符号 " + name)), fd);
    }

    public String version() throws Throwable {
        return cstr((MemorySegment) hVersion.invoke());
    }

    public FlowMint bindPort(short port) throws Throwable {
        hBindPort.invoke(ctx, port);
        return this;
    }

    public FlowMint setMitm(boolean enabled, boolean insecureUpstream) throws Throwable {
        hSetMitm.invoke(ctx, enabled, insecureUpstream);
        return this;
    }

    /** 设置 MITM CA（内存 PEM，不落地）；传 null 则用软件内置默认 CA。 */
    public FlowMint setCa(String certPem, String keyPem) throws Throwable {
        MemorySegment cert = certPem == null ? MemorySegment.NULL : arena.allocateUtf8String(certPem);
        MemorySegment key = keyPem == null ? MemorySegment.NULL : arena.allocateUtf8String(keyPem);
        hSetCa.invoke(ctx, cert, key);
        return this;
    }

    /** 安装当前生效 CA 到当前用户根存储（Windows）。 */
    public boolean installCa() throws Throwable {
        return (boolean) hInstallCa.invoke(ctx);
    }

    public FlowMint onHttp(Consumer<HttpEvent> h) throws Throwable {
        this.handler = h;
        MethodHandle target = MethodHandles.lookup()
                .findVirtual(FlowMint.class, "dispatch", MethodType.methodType(void.class, MemorySegment.class, MemorySegment.class))
                .bindTo(this);
        cbStub = LINKER.upcallStub(target, FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS), arena);
        hSetCb.invoke(ctx, cbStub, MemorySegment.NULL);
        return this;
    }

    /** 注册拦截改包回调。回调返回 CONTINUE/MODIFY/DROP；用 msg.set* 改写。 */
    public FlowMint onIntercept(java.util.function.ToIntFunction<Intercept> h) throws Throwable {
        this.interceptor = h;
        MethodHandle target = MethodHandles.lookup()
                .findVirtual(FlowMint.class, "dispatchIntercept", MethodType.methodType(int.class, MemorySegment.class, MemorySegment.class))
                .bindTo(this);
        icbStub = LINKER.upcallStub(target, FunctionDescriptor.of(I32, ValueLayout.ADDRESS, ValueLayout.ADDRESS), arena);
        hSetICb.invoke(ctx, icbStub, MemorySegment.NULL);
        return this;
    }

    public boolean exportCa(String outPath) throws Throwable {
        return (boolean) hExportCa.invoke(ctx, arena.allocateUtf8String(outPath));
    }

    public void start() throws Throwable {
        if (!(boolean) hStart.invoke(ctx)) {
            throw new IllegalStateException(cstr((MemorySegment) hLastErr.invoke(ctx)));
        }
    }

    public void stop() throws Throwable {
        hStop.invoke(ctx);
    }

    @Override
    public void close() {
        try {
            hFree.invoke(ctx);
        } catch (Throwable ignored) {
        }
        arena.close();
    }

    // 由 native 回调调用（工作线程）。
    @SuppressWarnings("unused")
    private void dispatch(MemorySegment ev, MemorySegment user) {
        try {
            HttpEvent e = new HttpEvent();
            e.type = (int) hEvType.invoke(ev);
            e.method = cstr((MemorySegment) hEvMethod.invoke(ev));
            e.url = cstr((MemorySegment) hEvUrl.invoke(ev));
            e.host = cstr((MemorySegment) hEvHost.invoke(ev));
            e.status = (int) hEvStatus.invoke(ev);
            e.body = readBody(ev);
            if (handler != null) handler.accept(e);
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    private byte[] readBody(MemorySegment ev) throws Throwable {
        MemorySegment lenSeg = arena.allocate(ValueLayout.JAVA_LONG);
        MemorySegment ptr = (MemorySegment) hEvBody.invoke(ev, lenSeg);
        long n = lenSeg.get(ValueLayout.JAVA_LONG, 0);
        if (n == 0 || ptr.address() == 0) return new byte[0];
        return ptr.reinterpret(n).toArray(ValueLayout.JAVA_BYTE);
    }

    // 由 native 拦截回调调用（工作线程），返回动作码。
    @SuppressWarnings("unused")
    private int dispatchIntercept(MemorySegment msg, MemorySegment user) {
        try {
            Intercept m = new Intercept(msg);
            return interceptor != null ? interceptor.applyAsInt(m) : CONTINUE;
        } catch (Throwable t) {
            t.printStackTrace();
            return CONTINUE;
        }
    }

    private byte[] readInterceptBody(MemorySegment msg) throws Throwable {
        MemorySegment lenSeg = arena.allocate(ValueLayout.JAVA_LONG);
        MemorySegment ptr = (MemorySegment) hIBody.invoke(msg, lenSeg);
        long n = lenSeg.get(ValueLayout.JAVA_LONG, 0);
        if (n == 0 || ptr.address() == 0) return new byte[0];
        return ptr.reinterpret(n).toArray(ValueLayout.JAVA_BYTE);
    }

    private static String cstr(MemorySegment p) {
        if (p.address() == 0) return "";
        return p.reinterpret(Long.MAX_VALUE).getUtf8String(0);
    }

    private static String locateDll() {
        String env = System.getenv("FLOWMINT_DLL");
        if (env != null && Files.exists(Path.of(env))) return env;
        String name = System.getProperty("os.name").toLowerCase().contains("win")
                ? "flowmint.dll" : "libflowmint.so";
        for (String cand : new String[]{
                "target/release/" + name, "target/debug/" + name,
                "../../target/release/" + name, "../../target/debug/" + name}) {
            if (Files.exists(Path.of(cand))) return Path.of(cand).toAbsolutePath().toString();
        }
        throw new RuntimeException("找不到 " + name + "；设置环境变量 FLOWMINT_DLL");
    }
}
