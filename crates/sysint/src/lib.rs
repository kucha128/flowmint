//! FlowMint 系统集成（Windows）：系统代理设置/关闭、CA 证书安装与安装状态检查。
//! 桌面应用与 SDK（FFI）共用同一实现。非 Windows 平台提供返回错误/false 的占位实现。

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
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
            InternetSetOptionW(
                ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                ptr::null_mut(),
                0,
            );
            InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_REFRESH, ptr::null_mut(), 0);
        }
    }

    fn settings_key() -> std::io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
    }

    /// 把系统代理设为 127.0.0.1:port 并开启。
    pub fn set_system_proxy(port: u16) -> Result<(), String> {
        let key = settings_key().map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyServer", &format!("127.0.0.1:{port}"))
            .map_err(|e| e.to_string())?;
        refresh_wininet();
        Ok(())
    }

    /// 关闭系统代理（ProxyEnable=0，清掉 ProxyServer）。不做"还原"。
    pub fn disable_system_proxy() -> Result<(), String> {
        let key = settings_key().map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &0u32)
            .map_err(|e| e.to_string())?;
        let _ = key.delete_value("ProxyServer");
        refresh_wininet();
        Ok(())
    }

    /// 把 CA（PEM）装进「当前用户 — 受信任的根证书颁发机构」。
    pub fn install_ca_pem(pem: &str) -> Result<(), String> {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push(format!("flowmint-ca-{}.pem", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).map_err(|e| format!("写临时证书失败: {e}"))?;
            f.write_all(pem.as_bytes())
                .map_err(|e| format!("写临时证书失败: {e}"))?;
        }
        let out = Command::new("certutil")
            .args(["-user", "-addstore", "-f", "Root"])
            .arg(&path)
            .output();
        let _ = std::fs::remove_file(&path);
        match out {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
            Err(e) => Err(format!("执行 certutil 失败: {e}")),
        }
    }

    /// 该 CA（DER）是否已装进当前用户根存储：按 SHA-1 指纹在 Root 里查。
    pub fn is_ca_installed(cert_der: &[u8]) -> bool {
        use sha1::{Digest, Sha1};
        let thumb = Sha1::digest(cert_der);
        let hex: String = thumb.iter().map(|b| format!("{b:02x}")).collect();
        match Command::new("certutil")
            .args(["-user", "-store", "Root", &hex])
            .output()
        {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn set_system_proxy(_port: u16) -> Result<(), String> {
        Err("系统代理仅支持 Windows".into())
    }
    pub fn disable_system_proxy() -> Result<(), String> {
        Err("系统代理仅支持 Windows".into())
    }
    pub fn install_ca_pem(_pem: &str) -> Result<(), String> {
        Err("安装证书仅支持 Windows".into())
    }
    pub fn is_ca_installed(_cert_der: &[u8]) -> bool {
        false
    }
}

pub use imp::{disable_system_proxy, install_ca_pem, is_ca_installed, set_system_proxy};
