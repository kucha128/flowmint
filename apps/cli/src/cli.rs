//! CLI command definitions (clap). Kept separate from execution so `main.rs`
//! only wires parsing to the `commands` modules.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "flowmint", version, about = "FlowMint 开发者网络平台 CLI")]
pub struct Cli {
    /// 本地索引 + chunk 存储的数据目录。
    #[arg(long, global = true, default_value = "data")]
    pub data: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// 抓包控制。
    #[command(subcommand)]
    Capture(CaptureCmd),
    /// 检索已捕获的 flow。
    #[command(subcommand)]
    Flow(FlowCmd),
    /// 导出捕获数据。
    #[command(subcommand)]
    Export(ExportCmd),
    /// Profile CA / 证书管理。
    #[command(subcommand)]
    Cert(CertCmd),
    /// Rule IR：校验并在已录制 flow 上离线回放。
    #[command(subcommand)]
    Rule(RuleCmd),
    /// MCP：只读 AI 工具服务器（stdio JSON-RPC）。
    #[command(subcommand)]
    Mcp(McpCmd),
    /// API：本地 REST 只读模型（loopback + bearer token）。
    #[command(subcommand)]
    Api(ApiCmd),
}

#[derive(Subcommand)]
pub enum CaptureCmd {
    /// 启动显式 HTTP 代理抓包（仅 loopback）。
    Start {
        /// 监听端口（绑定 127.0.0.1）。
        #[arg(long, default_value_t = 8888)]
        port: u16,
        /// 可选的会话标签。
        #[arg(long)]
        label: Option<String>,
        /// 开启 HTTPS 拦截（MITM），使用 profile CA。客户端需信任该 CA
        /// （见 `flowmint cert export`）。默认关闭。
        #[arg(long)]
        mitm: bool,
        /// 危险（仅测试 profile）：跳过上游 TLS 校验。仅用于你自己掌控的
        /// 源站，如自签名开发服务器。
        #[arg(long)]
        insecure_upstream: bool,
        /// 上游代理 host:port（把出站流量再转发给它，形成代理链）。
        #[arg(long)]
        upstream: Option<String>,
        /// 用内置默认证书（默认关闭，用本机生成的证书）。
        #[arg(long)]
        default_ca: bool,
    },
}

#[derive(Subcommand)]
pub enum FlowCmd {
    /// 按主机子串检索 flow。
    Search {
        #[arg(long)]
        host: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// 显示单条 flow 及其事件。
    Show { flow_id: String },
}

#[derive(Subcommand)]
pub enum ExportCmd {
    /// 导出捕获的 HTTP flow 为 HAR 1.2 文件。
    Har {
        #[arg(long, default_value = "capture.har")]
        out: PathBuf,
        #[arg(long)]
        host: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum CertCmd {
    /// 生成（如无）并导出本 profile 的 CA 证书以供信任。
    Export {
        /// CA PEM 写出路径（默认原地在 <data>/ca/ca.pem）。
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum RuleCmd {
    /// 校验规则文件（YAML 或 JSON）。
    Validate {
        #[arg(long)]
        rule: PathBuf,
    },
    /// 在某条已捕获 flow 上离线回放规则；打印决策 + diff。
    Test {
        #[arg(long)]
        rule: PathBuf,
        #[arg(long)]
        flow: String,
    },
}

#[derive(Subcommand)]
pub enum McpCmd {
    /// 以 stdio 提供只读 MCP 工具（默认只读、强制脱敏）。
    Serve,
}

#[derive(Subcommand)]
pub enum ApiCmd {
    /// 启动本地 REST API（127.0.0.1 + 每次启动随机 bearer token）。
    Serve {
        #[arg(long, default_value_t = 8899)]
        port: u16,
        /// 使用固定 token 而非随机（用于脚本/测试）。
        #[arg(long)]
        token: Option<String>,
    },
}
