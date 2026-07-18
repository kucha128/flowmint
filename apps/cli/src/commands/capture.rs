//! `capture start`：启动显式 HTTP 代理抓包。

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use flowmint_engine::Engine;

pub async fn start(
    engine: &Engine,
    data_dir: &Path,
    port: u16,
    label: Option<String>,
    mitm: bool,
    insecure_upstream: bool,
    upstream_proxy: Option<String>,
    use_default_ca: bool,
) -> Result<()> {
    let bind: SocketAddr = ([127, 0, 0, 1], port).into();
    println!("FlowMint 抓包代理: http://{bind}  (Ctrl-C 停止)");
    println!("  将客户端的 HTTP 代理设为 {bind}");
    if mitm {
        if use_default_ca {
            println!("  HTTPS MITM: 开 — 使用内置默认共享 CA（⚠️ 私钥公开，仅测试）");
        } else {
            let (path, _) = engine.ensure_ca()?;
            println!("  HTTPS MITM: 开 — 客户端需信任 CA: {}", path.display());
        }
        println!(
            "  (导出 CA: flowmint --data {} cert export)",
            data_dir.display()
        );
        if insecure_upstream {
            println!("  !! 已开启不校验上游 TLS（仅测试）");
        }
    } else {
        println!("  HTTPS MITM: 关（CONNECT 隧道仅记录元数据）");
    }

    if let Some(up) = &upstream_proxy {
        println!("  上游代理: {up}（出站流量经它转发）");
    }

    tokio::select! {
        res = engine.run_http_capture(bind, label, mitm, insecure_upstream, upstream_proxy, use_default_ca) => {
            res.context("抓包代理已停止")?;
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\n停止抓包；数据已写入 {}", data_dir.display());
        }
    }
    Ok(())
}
