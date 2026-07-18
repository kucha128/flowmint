//! Windows 桌面集成：一键设置/还原系统代理、安装 CA 证书。

use std::ffi::c_void;
use std::path::Path;
use std::process::Command;
use std::ptr;

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(h: *mut c_void, opt: u32, buf: *mut c_void, len: u32) -> i32;
}
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
const INTERNET_OPTION_REFRESH: u32 = 37;

/// 通知 WinINET 代理设置已变更，使已运行的应用即时生效。
fn refresh_wininet() {
    unsafe {
        InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, ptr::null_mut(), 0);
        InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_REFRESH, ptr::null_mut(), 0);
    }
}

/// 之前的系统代理设置，供还原（避免污染用户环境）。
#[derive(Clone)]
pub struct SavedProxy {
    enable: u32,
    server: String,
}

fn settings_key() -> std::io::Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
}

/// 读取当前系统代理设置（设置前备份用）。
pub fn read_proxy() -> SavedProxy {
    match RegKey::predef(HKEY_CURRENT_USER).open_subkey(INTERNET_SETTINGS) {
        Ok(k) => SavedProxy {
            enable: k.get_value("ProxyEnable").unwrap_or(0u32),
            server: k.get_value("ProxyServer").unwrap_or_default(),
        },
        Err(_) => SavedProxy { enable: 0, server: String::new() },
    }
}

/// 设为 127.0.0.1:port 的系统代理。
pub fn set_proxy(port: u16) -> std::io::Result<()> {
    let key = settings_key()?;
    key.set_value("ProxyEnable", &1u32)?;
    key.set_value("ProxyServer", &format!("127.0.0.1:{port}"))?;
    refresh_wininet();
    Ok(())
}

/// 还原到之前的系统代理设置。
pub fn restore_proxy(saved: &SavedProxy) -> std::io::Result<()> {
    let key = settings_key()?;
    key.set_value("ProxyEnable", &saved.enable)?;
    if saved.server.is_empty() {
        let _ = key.delete_value("ProxyServer");
    } else {
        key.set_value("ProxyServer", &saved.server)?;
    }
    refresh_wininet();
    Ok(())
}

/// 把 CA 安装到「当前用户 — 受信任的根证书颁发机构」。返回提示信息。
pub fn install_ca(pem_path: &Path) -> Result<String, String> {
    let out = Command::new("certutil")
        .args(["-user", "-addstore", "-f", "Root"])
        .arg(pem_path)
        .output()
        .map_err(|e| format!("执行 certutil 失败: {e}"))?;
    if out.status.success() {
        Ok("证书已安装到「当前用户 - 受信任的根证书颁发机构」".to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}
