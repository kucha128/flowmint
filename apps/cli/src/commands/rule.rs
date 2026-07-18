//! `rule validate` / `rule test`：规则校验与离线回放。

use std::path::Path;

use anyhow::{bail, Context, Result};
use flowmint_engine::Engine;
use flowmint_model::Rule;

/// 从 YAML/JSON 文件加载规则。
///
/// YAML 经 `serde_json::Value` 中转后再反序列化为 `Rule`，使外部标记的动作读作
/// `- redact: {...}`（serde_json 的单键 map 形式），而非 serde_yaml 0.9 的
/// `!redact` tag 形式。
pub fn load_rule(path: &Path) -> Result<Rule> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("读取规则 {}", path.display()))?;
    let value: serde_json::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("解析规则 {} (YAML/JSON)", path.display()))?;
    serde_json::from_value::<Rule>(value)
        .with_context(|| format!("解释规则 {}", path.display()))
}

pub fn validate(path: &Path) -> Result<()> {
    let r = load_rule(path)?;
    println!(
        "ok: 规则 '{}' v{} — {} 个动作, fallback {:?}",
        r.id,
        r.version,
        r.actions.len(),
        r.fallback
    );
    Ok(())
}

pub fn test(engine: &Engine, rule_path: &Path, flow: &str) -> Result<()> {
    let r = load_rule(rule_path)?;
    let Some((decision, changes)) = engine.replay_rule_on_flow(flow, &r)? else {
        bail!("未找到 flow {flow}");
    };

    println!("规则 '{}' 对 flow {flow}", r.id);
    println!("  matched: {}", decision.matched);
    if !decision.actions_applied.is_empty() {
        println!("  actions: {}", decision.actions_applied.join(", "));
    }
    if !decision.redacted.is_empty() {
        println!("  redacted: {}", decision.redacted.join(", "));
    }
    if decision.delay_ms > 0 {
        println!("  delay: {}ms", decision.delay_ms);
    }
    if let Some(sc) = &decision.short_circuit {
        println!("  short-circuit: {} {}", sc.status, sc.body);
    }
    for e in &decision.errors {
        println!("  error: {e}");
    }
    println!("  --- diff ({} 处变化) ---", changes.len());
    for c in &changes {
        println!(
            "  {}: {} -> {}",
            c.location,
            c.before.as_deref().unwrap_or("∅"),
            c.after.as_deref().unwrap_or("∅"),
        );
    }
    Ok(())
}
