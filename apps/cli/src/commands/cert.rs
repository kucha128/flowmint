//! `cert export`：生成并导出 profile 的 MITM CA 证书。

use std::path::PathBuf;

use anyhow::Result;
use flowmint_engine::Engine;

pub fn export(engine: &Engine, out: Option<PathBuf>) -> Result<()> {
    let (path, pem) = engine.ensure_ca()?;
    match out {
        Some(dest) => {
            std::fs::write(&dest, &pem)?;
            println!("CA 已导出到 {}", dest.display());
        }
        None => println!("profile CA 位于 {}\n\n{}", path.display(), pem),
    }
    println!("仅在你拥有且被授权测试的设备上安装/信任该 CA。");
    Ok(())
}
