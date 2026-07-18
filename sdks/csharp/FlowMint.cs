// FlowMint C# SDK —— C ABI 核心（flowmint）的 P/Invoke 薄绑定。
//
// 用法（回调式嵌入）：
//     using var fm = new FlowMint.FlowMint();
//     fm.BindPort(8888);
//     fm.OnHttp(ev => Console.WriteLine($"{ev.Method} {ev.Url} {ev.Status}"));
//     fm.Start();   // 让客户端走 127.0.0.1:8888 代理
//
// 定位 DLL：环境变量 FLOWMINT_DLL > 应用目录/PATH 下的 flowmint.dll。

using System.Runtime.InteropServices;

namespace FlowMint;

public sealed class HttpEvent
{
    public int Type;               // 0=请求, 1=响应
    public string Method = "";
    public string Url = "";
    public string Host = "";
    public int Status;             // 请求为 -1
    public byte[] Body = System.Array.Empty<byte>();

    public bool IsRequest => Type == 0;
    public bool IsResponse => Type == 1;
}

// 拦截动作码（OnIntercept 回调返回值）。
public enum InterceptAction { Continue = 0, Modify = 1, Drop = 2 }

// 一条在途消息：读字段，用 Set* 改写，回调返回动作码。
public sealed class Intercept
{
    private readonly nint _msg;
    internal Intercept(nint msg)
    {
        _msg = msg;
        IsResponse = FlowMint.fm_intercept_is_response(msg) != 0;
        Method = Native.Utf8(FlowMint.fm_intercept_method(msg));
        Url = Native.Utf8(FlowMint.fm_intercept_url(msg));
        Status = FlowMint.fm_intercept_status(msg);
        Body = FlowMint.ReadInterceptBody(msg);
    }
    public bool IsResponse { get; }
    public bool IsRequest => !IsResponse;
    public string Method { get; } = "";
    public string Url { get; } = "";
    public int Status { get; }
    public byte[] Body { get; } = System.Array.Empty<byte>();

    public void SetBody(byte[] data) => FlowMint.fm_intercept_set_body(_msg, data, (nuint)data.Length);
    public void SetStatus(int status) => FlowMint.fm_intercept_set_status(_msg, status);
    public void SetHeader(string name, string value) => FlowMint.fm_intercept_set_header(_msg, name, value);
}

public sealed class FlowMint : System.IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void HttpCallback(nint ev, nint user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int InterceptCallback(nint msg, nint user);

    private nint _ctx;
    private HttpCallback? _cb; // 持有委托，防止 GC
    private InterceptCallback? _icb; // 拦截回调（同上）

    static FlowMint()
    {
        // 让 DllImport 的 "flowmint" 能从 FLOWMINT_DLL 指定的路径加载。
        NativeLibrary.SetDllImportResolver(typeof(FlowMint).Assembly, (name, asm, path) =>
        {
            if (name != "flowmint") return nint.Zero;
            var env = System.Environment.GetEnvironmentVariable("FLOWMINT_DLL");
            if (!string.IsNullOrEmpty(env) && System.IO.File.Exists(env))
                return NativeLibrary.Load(env);
            return NativeLibrary.TryLoad(name, asm, path, out var h) ? h : nint.Zero;
        });
    }

    public FlowMint()
    {
        _ctx = fm_context_new();
    }

    public string Version() => Native.Utf8(fm_version());

    public FlowMint BindPort(ushort port) { fm_bind_port(_ctx, port); return this; }

    public FlowMint SetMitm(bool enabled, bool insecureUpstream = false)
    {
        fm_set_mitm(_ctx, enabled, insecureUpstream);
        return this;
    }

    // 设置 MITM CA（内存 PEM，不落地）；传 null 则用软件内置默认 CA。
    public FlowMint SetCa(string? certPem, string? keyPem) { fm_set_ca(_ctx, certPem, keyPem); return this; }

    // 安装当前生效 CA 到当前用户根存储（Windows）。
    public bool InstallCa() => fm_install_ca(_ctx);

    public FlowMint OnHttp(System.Action<HttpEvent> handler)
    {
        _cb = (ev, _) => handler(ReadEvent(ev));
        fm_set_http_callback(_ctx, _cb, nint.Zero);
        return this;
    }

    // 注册拦截改包回调。回调返回 InterceptAction；用 msg.Set* 改写。
    public FlowMint OnIntercept(System.Func<Intercept, InterceptAction> handler)
    {
        _icb = (msg, _) => (int)handler(new Intercept(msg));
        fm_set_intercept_callback(_ctx, _icb, nint.Zero);
        return this;
    }

    public bool ExportCa(string outPath) => fm_export_ca(_ctx, outPath);

    public void Start()
    {
        if (!fm_start(_ctx))
            throw new System.InvalidOperationException(LastError());
    }

    public void Stop() => fm_stop(_ctx);

    public string LastError() => Native.Utf8(fm_last_error(_ctx));

    public void Dispose()
    {
        if (_ctx != nint.Zero)
        {
            fm_context_free(_ctx);
            _ctx = nint.Zero;
        }
    }

    private static HttpEvent ReadEvent(nint ev) => new()
    {
        Type = fm_http_event_type(ev),
        Method = Native.Utf8(fm_http_event_method(ev)),
        Url = Native.Utf8(fm_http_event_url(ev)),
        Host = Native.Utf8(fm_http_event_host(ev)),
        Status = fm_http_event_status(ev),
        Body = ReadBody(ev),
    };

    private static byte[] ReadBody(nint ev)
    {
        nint ptr = fm_http_event_body(ev, out nuint len);
        if (ptr == nint.Zero || len == 0) return System.Array.Empty<byte>();
        var buf = new byte[len];
        Marshal.Copy(ptr, buf, 0, (int)len);
        return buf;
    }

    internal static byte[] ReadInterceptBody(nint msg)
    {
        nint ptr = fm_intercept_body(msg, out nuint len);
        if (ptr == nint.Zero || len == 0) return System.Array.Empty<byte>();
        var buf = new byte[len];
        Marshal.Copy(ptr, buf, 0, (int)len);
        return buf;
    }

    // ---- P/Invoke 声明 ----
    private const string L = "flowmint";

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_context_new();
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_context_free(nint ctx);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_bind_port(nint ctx, ushort port);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_set_mitm(nint ctx, [MarshalAs(UnmanagedType.I1)] bool mitm, [MarshalAs(UnmanagedType.I1)] bool insecure);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_set_ca(nint ctx, [MarshalAs(UnmanagedType.LPUTF8Str)] string? certPem, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPem);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)][return: MarshalAs(UnmanagedType.I1)] private static extern bool fm_install_ca(nint ctx);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_set_http_callback(nint ctx, HttpCallback cb, nint user);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)][return: MarshalAs(UnmanagedType.I1)] private static extern bool fm_start(nint ctx);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_stop(nint ctx);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_last_error(nint ctx);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)][return: MarshalAs(UnmanagedType.I1)] private static extern bool fm_export_ca(nint ctx, [MarshalAs(UnmanagedType.LPUTF8Str)] string outPath);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_version();
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern int fm_http_event_type(nint ev);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_http_event_method(nint ev);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_http_event_url(nint ev);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_http_event_host(nint ev);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern int fm_http_event_status(nint ev);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern nint fm_http_event_body(nint ev, out nuint len);
    // 拦截改包
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] private static extern void fm_set_intercept_callback(nint ctx, InterceptCallback cb, nint user);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern int fm_intercept_is_response(nint msg);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern nint fm_intercept_method(nint msg);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern nint fm_intercept_url(nint msg);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern int fm_intercept_status(nint msg);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern nint fm_intercept_body(nint msg, out nuint len);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern void fm_intercept_set_body(nint msg, byte[] data, nuint len);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern void fm_intercept_set_status(nint msg, int status);
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)] internal static extern void fm_intercept_set_header(nint msg, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string value);
}

internal static class Native
{
    public static string Utf8(nint p) => p == nint.Zero ? "" : Marshal.PtrToStringUTF8(p) ?? "";
}
