//! `flowmint` CLI 入口：初始化日志、解析命令、分发到 `commands` 各模块。

mod cli;
mod commands;

use anyhow::{Context, Result};
use clap::Parser;
use flowmint_engine::Engine;
use tracing_subscriber::EnvFilter;

use cli::{ApiCmd, CaptureCmd, CertCmd, Cli, Command, ExportCmd, FlowCmd, McpCmd, RuleCmd};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let engine =
        Engine::open(&cli.data).with_context(|| format!("打开数据目录 {}", cli.data.display()))?;

    match cli.command {
        Command::Capture(CaptureCmd::Start {
            port,
            label,
            mitm,
            insecure_upstream,
            upstream,
            default_ca,
        }) => {
            commands::capture::start(
                &engine,
                &cli.data,
                port,
                label,
                mitm,
                insecure_upstream,
                upstream,
                default_ca,
            )
            .await?
        }
        Command::Flow(FlowCmd::Search { host, limit }) => {
            commands::flow::search(&engine, host, limit)?
        }
        Command::Flow(FlowCmd::Show { flow_id }) => commands::flow::show(&engine, &flow_id)?,
        Command::Export(ExportCmd::Har { out, host }) => {
            commands::export::har(&engine, &out, host.as_deref())?
        }
        Command::Cert(CertCmd::Export { out }) => commands::cert::export(&engine, out)?,
        Command::Rule(RuleCmd::Validate { rule }) => commands::rule::validate(&rule)?,
        Command::Rule(RuleCmd::Test { rule, flow }) => commands::rule::test(&engine, &rule, &flow)?,
        Command::Mcp(McpCmd::Serve) => commands::mcp::serve(engine)?,
        Command::Api(ApiCmd::Serve { port, token }) => {
            commands::api::serve(engine, port, token).await?
        }
    }
    Ok(())
}
