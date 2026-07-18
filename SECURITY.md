# 安全策略 / Security Policy

## 授权使用（重要）

FlowMint 是可解密并改写网络流量的中间人（MITM）工具，仅供在**你拥有或已获明确授权**的
设备与流量上做开发调试、测试与安全研究。请勿用于未授权的拦截或任何违反当地法律法规、
服务条款的行为。工具本身不实现绕过证书锁定、访问控制或系统安全机制的能力。

## 报告漏洞 / Reporting a Vulnerability

如发现安全漏洞，请**不要**公开提交 issue，改为私下报告：

- 通过 GitHub 的 **Security Advisories**（仓库 → Security → Report a vulnerability）私下提交；或
- 邮件联系维护者（请在下方填写联系邮箱）：`<security@your-domain>`

请附上复现步骤、影响范围与（如有）修复建议。我们会尽快确认并在修复后致谢。

## 支持范围

- 仅对 `main` 分支的最新版本提供安全修复。
- 依赖的安全公告建议在 CI 中通过 `cargo deny` / `cargo audit` 持续监控。

## 设计上的安全边界

- 代理默认仅监听 loopback（`127.0.0.1`）。
- HTTPS MITM 默认关闭，需用户显式信任本地 CA；未开启时 CONNECT 隧道仅记录元数据、不解密。
- 每个 profile 独立 CA，私钥存于本地数据目录（已在 `.gitignore` 中排除，切勿提交）。
- AI/MCP 接口默认只读、强制脱敏。
