# FlowMint（流铸）

**中文** | [English](README.en.md)

面向开发者的**网络行为分析与开发平台**：把已观察、已验证的网络流量（Flow）铸造成可复用、可测试、可部署的软件网络逻辑（Mint）。

包含一个对标 Fiddler/Charles 的**桌面 MITM 分析器**、一套命令行工具、可跨端一致执行的 **Rule IR**，以及嵌入自有程序的**多语言抓包/改包 SDK**。

核心目标（优先级从高到低）：**使用方便 → 分析效率高 → 分析完接入开发简单**。

> ⚠️ **授权使用与免责声明**
> FlowMint 是一款可解密并改写网络流量的中间人（MITM）调试工具，**仅供在你拥有或已获得明确书面授权的设备与流量上做开发调试、测试与安全研究**。
> 你须自行遵守所在地法律法规及相关服务条款。作者与贡献者对任何滥用、未授权拦截或由此产生的损害**不承担任何责任**（详见 [LICENSE](LICENSE)）。
> FlowMint **不**实现、也不用于绕过证书锁定、访问控制或任何系统安全机制。

---

## 📖 文档导航

| 文档 | 内容 |
|---|---|
| [目录结构与子项目](docs/目录结构与子项目.md) | 整个项目的目录结构，以及每个子项目的职责 |
| [使用指南](docs/使用指南.md) | 桌面应用与 CLI 的具体用法 |
| [构建与运行](docs/构建与运行.md) | 各子项目如何构建、运行（含桌面应用出独立 exe 的注意事项） |
| [多语言 SDK 开发](docs/SDK开发.md) | C ABI 核心 + 各语言（C/C++/C#/Go/Java/Python/易语言）绑定 |
| [开发规范](docs/开发规范.md) | 目录/代码/文档/Git 的强制规范 |
| [设计文档](docs/设计文档.md) | 完整架构设计与取舍（原始设计基线） |

> 新增/删除/改名文档时，必须同步更新本表（见[开发规范](docs/开发规范.md)）。

---

## 🧩 子项目一览

Rust workspace（多 crate）+ Tauri 桌面应用 + 多语言 SDK。详见[目录结构与子项目](docs/目录结构与子项目.md)。

| 子项目 | 位置 | 作用 |
|---|---|---|
| 数据契约 | [crates/model](crates/model) | 事件模型、Flow、Rule IR、ID、时钟、错误（其它 crate 的公共基础） |
| 存储 | [crates/storage](crates/storage) | SQLite 索引 + 内容寻址 chunk 存储 |
| TLS/CA | [crates/tls](crates/tls) | 每 profile CA、按需签发 leaf、MITM 的 rustls 配置 |
| 抓包适配器 | [crates/proxy-http](crates/proxy-http) | HTTP 代理 + CONNECT 隧道 + HTTPS MITM + WebSocket 帧捕获 |
| 规则引擎 | [crates/rules](crates/rules) | Rule IR 执行器（匹配、动作、前后 diff） |
| 引擎 | [crates/engine](crates/engine) | 抓包生命周期、实时广播、查询/回放/导出（串联各 crate） |
| REST API | [crates/api](crates/api) | 本地只读 API（loopback + token） |
| MCP | [crates/mcp](crates/mcp) | 只读 AI 工具 + stdio 服务器 + 脱敏 |
| C ABI 核心 | [crates/ffi](crates/ffi) | 编成 `flowmint` 动态库，供多语言 SDK 薄绑定复用 |
| CLI | [apps/cli](apps/cli) | 命令行工具 `flowmint` |
| 桌面应用 | [apps/desktop](apps/desktop) | Tauri 2 桌面分析器（React 前端 + Rust 后端） |
| 多语言 SDK | [sdks/](sdks/) | C/C++/C#/Go/Java/Python/易语言 绑定同一 C ABI（见 [SDK 开发](docs/SDK开发.md)） |

---

## 🚀 快速开始

### 桌面应用（推荐）

```powershell
cd apps\desktop
npm install
npm run tauri build -- --no-bundle
# 双击 apps\desktop\src-tauri\target\release\flowmint-studio.exe
```

打开后点「▶ 开始抓包」，把客户端代理指向 `127.0.0.1:8888`，流量实时出现。详见[使用指南](docs/使用指南.md)。

> **HTTPS 解密的证书**：默认用**内置默认证书**，开箱即用——开 MITM 后到设置里点「使用默认证书」信任即可。想要每台机器唯一的私有证书，就点「创建新证书」（生成到 `<exe目录>/data/ca/`）。其它设备（手机等）可在浏览器打开 `http://<本机IP>:端口/` 下载安装。SDK 同理：`fm_set_ca` 传空用默认证书，传你自己的 PEM 则用私有证书。

### 命令行（无界面 / CI / 自动化伴生工具）

`flowmint.exe` 面向**没有图形界面**的场景：服务器/headless 抓包、在 CI 里校验与回放规则、以 MCP/REST 把抓到的数据喂给 AI 或外部脚本——这些是桌面（要 GUI）和 SDK（要写宿主代码）覆盖不到的。

```powershell
cargo build --workspace
cargo run -p flowmint-cli -- --data mydata capture start --port 8888
# 另开终端：curl.exe -x http://127.0.0.1:8888 http://目标/
cargo run -p flowmint-cli -- --data mydata flow search
cargo run -p flowmint-cli -- --data mydata rule test --rule r.yaml --flow <flow_id>  # CI 里回放规则看 diff
cargo run -p flowmint-cli -- --data mydata mcp serve   # 只读 MCP，供 AI 接入
```

---

## ✅ 能力与边界

- **已实现**：HTTP 抓包、HTTPS MITM（含证书下载页/各平台安装）、WebSocket 帧捕获（桌面可**主动断开** WS/隧道连接）、响应体解压、完整 header 与 Body、**断点改包**、**请求重放/构造器**、**上游代理链**、系统代理一键开关、按进程归属、Rule IR 执行 + 离线回放 + diff、只读 MCP、本地 REST API、桌面分析器、多语言抓包 SDK（C ABI，含 **HTTP 拦截改包**与 **WebSocket 帧拦截改写/丢弃/主动断开**）。
- **尚未实现**（按设计分期）：TCP/UDP 语义改写、WebSocket/TCP/UDP SDK 回调、Wasm 插件、OS 驱动/TUN、HTTP/3、远程受管 agent。
- **安全边界**：默认仅监听 loopback；MITM 默认关闭且需显式信任 CA；CONNECT 隧道不解密仅记元数据；AI/MCP 默认只读、强制脱敏。仅用于你有权观测与修改的流量。

## 💬 交流与反馈

- QQ 交流群：**342696759**
- 问题、建议、Bug：欢迎提 [Issue](../../issues)。

## 📜 许可证与安全

[MIT](LICENSE)。复用第三方组件须遵循其许可证并维护 `THIRD_PARTY_NOTICES`。安全策略与漏洞报告见 [SECURITY.md](SECURITY.md)。
