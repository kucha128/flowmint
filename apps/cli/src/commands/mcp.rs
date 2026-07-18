//! `mcp serve`：以 stdio 提供只读 MCP 工具服务器。

use anyhow::Result;
use flowmint_engine::Engine;

pub fn serve(engine: Engine) -> Result<()> {
    // 只读、等价 loopback（stdio）的 AI 接口（设计 §10.3）。
    flowmint_mcp::server::serve_stdio(engine)?;
    Ok(())
}
