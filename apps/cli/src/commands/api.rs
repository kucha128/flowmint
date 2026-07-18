//! `api serve`：启动本地 REST 只读 API。

use std::net::SocketAddr;

use anyhow::{Context, Result};
use flowmint_engine::Engine;

pub async fn serve(engine: Engine, port: u16, token: Option<String>) -> Result<()> {
    let bind: SocketAddr = ([127, 0, 0, 1], port).into();
    let token = token.unwrap_or_else(flowmint_api::new_token);
    println!("FlowMint API: http://{bind}  (Ctrl-C 停止)");
    println!("  token: {token}");
    println!("  示例: curl -H \"authorization: Bearer {token}\" http://{bind}/flows");
    tokio::select! {
        res = flowmint_api::serve(engine, bind, token) => { res.context("API 服务已停止")?; }
        _ = tokio::signal::ctrl_c() => { println!("\n停止 API"); }
    }
    Ok(())
}
