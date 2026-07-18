//! `flow search` / `flow show`：检索与查看已捕获的 flow。

use anyhow::{bail, Result};
use flowmint_engine::Engine;
use flowmint_storage::SearchFilter;

pub fn search(engine: &Engine, host: Option<String>, limit: usize) -> Result<()> {
    let flows = engine.search_flows(&SearchFilter {
        host,
        capture_id: None,
        limit,
    })?;
    if flows.is_empty() {
        println!("(无 flow)");
    }
    for f in &flows {
        println!(
            "{}  {:<6} {:<3} {}{}",
            f.flow_id,
            f.method
                .as_deref()
                .unwrap_or(f.l7.as_deref().unwrap_or("-")),
            f.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            f.host.as_deref().unwrap_or("-"),
            f.path.as_deref().unwrap_or(""),
        );
    }
    Ok(())
}

pub fn show(engine: &Engine, flow_id: &str) -> Result<()> {
    let Some(flow) = engine.get_flow(flow_id)? else {
        bail!("未找到 flow {flow_id}");
    };
    println!("{}", serde_json::to_string_pretty(&flow)?);
    println!("--- events ---");
    for ev in engine.events_for_flow(flow_id)? {
        let bytes = match &ev.payload {
            Some(p) => format!(
                " payload={}B sha={}",
                p.length,
                &p.sha256[..8.min(p.sha256.len())]
            ),
            None => String::new(),
        };
        println!(
            "  #{} {:?} {:?}{}",
            ev.sequence, ev.direction, ev.kind, bytes
        );
    }
    Ok(())
}
