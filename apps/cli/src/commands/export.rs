//! `export har`：导出捕获的 HTTP flow 为 HAR 1.2。

use std::path::Path;

use anyhow::Result;
use flowmint_engine::Engine;

pub fn har(engine: &Engine, out: &Path, host: Option<&str>) -> Result<()> {
    let n = engine.export_har(out, host)?;
    println!("已导出 {n} 条 HTTP flow 到 {}", out.display());
    Ok(())
}
