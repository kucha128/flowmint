//! FlowMint Studio — desktop MITM analyzer backend (Tauri v2).
//!
//! Embeds the FlowMint engine, drives capture, streams live flows to the UI and
//! answers detail/query commands.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;

use flowmint_engine::Engine;
use flowmint_storage::SearchFilter;
use flowmint_sysint as sysint;
use tauri::{async_runtime, Emitter, Manager, State};

struct AppState {
    engine: Engine,
    task: Mutex<Option<async_runtime::JoinHandle<()>>>,
    port: Mutex<Option<u16>>,
    data_dir: PathBuf,
}

#[tauri::command]
async fn start_capture(
    state: State<'_, AppState>,
    port: u16,
    mitm: bool,
    insecure: bool,
    upstream: Option<String>,
    use_default_ca: bool,
) -> Result<(), String> {
    if let Some(h) = state.task.lock().unwrap().take() {
        h.abort();
    }
    let engine = state.engine.clone();
    let bind = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    // 空串视为不设上游代理。
    let upstream = upstream.filter(|s| !s.trim().is_empty());
    let handle = async_runtime::spawn(async move {
        if let Err(e) = engine
            .run_http_capture(bind, None, mitm, insecure, upstream, use_default_ca)
            .await
        {
            eprintln!("capture stopped: {e}");
        }
    });
    *state.task.lock().unwrap() = Some(handle);
    *state.port.lock().unwrap() = Some(port);
    Ok(())
}

#[tauri::command]
async fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(h) = state.task.lock().unwrap().take() {
        h.abort();
    }
    *state.port.lock().unwrap() = None;
    Ok(())
}

#[tauri::command]
fn capture_status(state: State<'_, AppState>) -> Option<u16> {
    *state.port.lock().unwrap()
}

#[tauri::command]
fn search_flows(
    state: State<'_, AppState>,
    host: String,
    limit: usize,
) -> Result<serde_json::Value, String> {
    let host = if host.trim().is_empty() { None } else { Some(host) };
    let flows = state
        .engine
        .search_flows(&SearchFilter { host, capture_id: None, limit })
        .map_err(|e| e.to_string())?;
    serde_json::to_value(flows).map_err(|e| e.to_string())
}

#[tauri::command]
fn flow_detail(state: State<'_, AppState>, flow_id: String) -> Result<serde_json::Value, String> {
    state
        .engine
        .flow_detail(&flow_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "flow not found".to_string())
}

#[tauri::command]
fn export_har(state: State<'_, AppState>, host: Option<String>) -> Result<String, String> {
    let out = state.data_dir.join("capture.har");
    let n = state
        .engine
        .export_har(&out, host.as_deref())
        .map_err(|e| e.to_string())?;
    Ok(format!("{} ({n} flows)", out.display()))
}

/// 安装当前生效的 CA 到当前用户根存储（HTTPS 解密所需）。
/// `use_default_ca=true` 装内置默认 CA，否则装本机生成的 CA。
#[tauri::command]
fn install_ca(state: State<'_, AppState>, use_default_ca: bool) -> Result<String, String> {
    let pem = state
        .engine
        .active_ca_pem(use_default_ca)
        .map_err(|e| e.to_string())?;
    sysint::install_ca_pem(&pem).map(|_| "证书已安装到「当前用户 - 受信任的根证书颁发机构」".to_string())
}

/// 当前生效的 CA 是否已装进用户根存储。
#[tauri::command]
fn is_ca_installed(state: State<'_, AppState>, use_default_ca: bool) -> Result<bool, String> {
    let ca = state.engine.active_ca(use_default_ca).map_err(|e| e.to_string())?;
    Ok(sysint::is_ca_installed(&ca.ca_der()))
}

/// 删除本机 CA 并重新生成一张全新的（「创建新证书」）。
#[tauri::command]
fn regenerate_ca(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.regenerate_ca().map(|_| ()).map_err(|e| e.to_string())
}

/// 主动断开一个进行中的连接（WS 会话 / 隧道），按 flow_id。
/// 返回该连接当时是否仍在进行。
#[tauri::command]
fn disconnect_flow(state: State<'_, AppState>, flow_id: String) -> Result<bool, String> {
    Ok(state.engine.disconnect_flow(&flow_id))
}

/// 把系统代理设为 127.0.0.1:port 并开启。
#[tauri::command]
fn set_system_proxy(_state: State<'_, AppState>, port: u16) -> Result<(), String> {
    sysint::set_system_proxy(port)
}

/// 关闭系统代理。
#[tauri::command]
fn clear_system_proxy(_state: State<'_, AppState>) -> Result<(), String> {
    sysint::disable_system_proxy()
}

/// 重放 / 构造器：发送一条请求，返回响应。
#[tauri::command]
async fn send_request(
    state: State<'_, AppState>,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
    insecure: bool,
) -> Result<serde_json::Value, String> {
    state
        .engine
        .send_request(&method, &url, headers, body.into_bytes(), insecure)
        .await
        .map_err(|e| e.to_string())
}

/// 配置断点：开关、主机过滤、是否也拦截响应。
#[tauri::command]
fn set_breakpoints(state: State<'_, AppState>, enabled: bool, host_filter: Option<String>, break_response: bool) {
    state.engine.set_breakpoints(enabled, host_filter, break_response);
}

/// 对某个挂起消息放行 / 修改放行 / 丢弃。
#[tauri::command]
fn resume_breakpoint(
    state: State<'_, AppState>,
    id: u64,
    action: String,
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: String,
) {
    state.engine.resume_breakpoint(id, &action, status, headers, body.into_bytes());
}

/// 程序所在目录（可移植：数据与配置都放这里，不污染系统其它目录）。
fn run_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn data_dir() -> PathBuf {
    run_dir().join("data")
}

fn config_path() -> PathBuf {
    run_dir().join("flowmint.config.json")
}

/// 持久化到运行目录的界面设置。
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct AppConfig {
    port: u16,
    mitm: bool,
    insecure: bool,
    upstream: String,
    #[serde(default)]
    use_default_ca: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            port: 8888,
            mitm: false,
            insecure: false,
            upstream: String::new(),
            use_default_ca: true, // 默认用内置默认证书，省去每台机器生成/信任
        }
    }
}

/// 读取配置（不存在或损坏时返回默认值）。
#[tauri::command]
fn get_config() -> AppConfig {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// 保存配置到运行目录的 flowmint.config.json。
#[tauri::command]
fn set_config(config: AppConfig) -> Result<(), String> {
    let s = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(config_path(), s).map_err(|e| e.to_string())
}

/// 真正清空存储：删除所有 flow/event 与 chunk 磁盘文件（不同于仅清界面列表）。
#[tauri::command]
fn clear_storage(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.clear_storage().map_err(|e| e.to_string())
}

fn main() {
    let dir = data_dir();
    let engine = Engine::open(&dir).expect("failed to open FlowMint engine");
    let stream_engine = engine.clone();

    tauri::Builder::default()
        // 禁止多开：再次启动时不新开进程，而是把已运行的窗口拉到前台。
        // 该插件必须最先注册。
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let win = app
                .get_webview_window("main")
                .or_else(|| app.webview_windows().into_values().next());
            if let Some(w) = win {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .manage(AppState {
            engine,
            task: Mutex::new(None),
            port: Mutex::new(None),
            data_dir: dir,
        })
        .setup(move |app| {
            // Bridge engine live flow broadcast → Tauri "flow" events.
            let handle = app.handle().clone();
            let eng = stream_engine.clone();
            async_runtime::spawn(async move {
                let mut rx = eng.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(flow) => {
                            let _ = handle.emit("flow", flow);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            // 实时 WebSocket 帧 → Tauri "ws_frame" 事件（界面追加，无需轮询）。
            let fr_handle = app.handle().clone();
            let fr_eng = stream_engine.clone();
            async_runtime::spawn(async move {
                let mut rx = fr_eng.subscribe_frames();
                loop {
                    match rx.recv().await {
                        Ok(frame) => {
                            let _ = fr_handle.emit("ws_frame", frame);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            // 断点挂起消息 → Tauri "breakpoint" 事件。
            let bp_handle = app.handle().clone();
            let bp_eng = stream_engine.clone();
            async_runtime::spawn(async move {
                let mut rx = bp_eng.subscribe_breakpoints();
                loop {
                    match rx.recv().await {
                        Ok(ev) => {
                            let _ = bp_handle.emit("breakpoint", ev);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_capture,
            stop_capture,
            capture_status,
            search_flows,
            flow_detail,
            export_har,
            install_ca,
            is_ca_installed,
            set_system_proxy,
            clear_system_proxy,
            disconnect_flow,
            send_request,
            set_breakpoints,
            resume_breakpoint,
            get_config,
            set_config,
            clear_storage,
            regenerate_ca,
        ])
        .run(tauri::generate_context!())
        .expect("error while running FlowMint Studio");
}
