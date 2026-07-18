// 关于 / 设置 模态对话框，复用通用 Modal。
import { useState } from "react";
import { Modal } from "./Modal";

export function AboutDialog({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="关于 FlowMint Studio" onClose={onClose} width={400}>
      <div className="about">
        <div className="about-logo">Flow<span>Mint</span> Studio</div>
        <p className="muted">面向开发者的网络行为分析与调试平台。</p>
        <div className="kv">
          <span className="k">能力</span><span>HTTP/HTTPS(MITM)/WebSocket 抓包、解密、断点改包、重放</span>
          <span className="k">运行时</span><span>Tauri 2 · Rust 引擎 · React 前端</span>
        </div>
      </div>
    </Modal>
  );
}

interface SettingsProps {
  onClose: () => void;
  running: number | null;
  port: number;
  setPort: (n: number) => void;
  mitm: boolean;
  onMitm: (v: boolean) => void;
  insecure: boolean;
  onInsecure: (v: boolean) => void;
  upstream: string;
  onSave: (upstream: string) => void; // 保存端口/上游/MITM 到配置并（抓包中）重启生效
  useDefaultCa: boolean;
  onDefaultCa: (v: boolean) => void;
  onInstallCa: () => void;
}

const TABS = ["代理", "HTTPS 解密"] as const;

export function SettingsDialog(p: SettingsProps) {
  const [tab, setTab] = useState<(typeof TABS)[number]>("代理");
  const [up, setUp] = useState(p.upstream);

  const footer = (
    <>
      <button onClick={p.onClose}>取消</button>
      <button className="primary" onClick={() => {
        p.onSave(up);
        p.onClose();
      }}>保存</button>
    </>
  );

  return (
    <Modal title="设置" onClose={p.onClose} width={480} footer={footer}>
      <div className="set-tabs">
        {TABS.map((t) => (
          <div key={t} className={"set-tab" + (tab === t ? " active" : "")} onClick={() => setTab(t)}>{t}</div>
        ))}
      </div>

      <div className="settings">
        {tab === "代理" && (
          <>
            <label className="field">
              <span>代理监听端口</span>
              <input type="number" value={p.port} disabled={p.running != null}
                onChange={(e) => p.setPort(+e.target.value)} />
              {p.running != null && <em className="muted">停止抓包后可改</em>}
            </label>
            <label className="field">
              <span>上游代理 (host:port)</span>
              <input type="text" placeholder="例如 127.0.0.1:10809，留空为直连"
                value={up} onChange={(e) => setUp(e.target.value)} />
              <em className="muted">出站流量再转发给它，形成代理链。保存后生效（抓包中会重启代理）。</em>
            </label>
          </>
        )}

        {tab === "HTTPS 解密" && (
          <>
            <label className="chk-row">
              <input type="checkbox" checked={p.mitm} onChange={(e) => p.onMitm(e.target.checked)} />
              <span>解密 HTTPS（MITM）</span>
            </label>
            {p.mitm && (
              <label className="chk-row">
                <input type="checkbox" checked={p.insecure} onChange={(e) => p.onInsecure(e.target.checked)} />
                <span>不校验上游证书（仅测试自签名服务器）</span>
              </label>
            )}
            <div className="field">
              <span>使用哪张 CA</span>
              <label className="chk-row">
                <input type="radio" name="casrc" checked={!p.useDefaultCa}
                  onChange={() => p.onDefaultCa(false)} />
                <span>本机生成（更安全，推荐）—— 每机唯一、私钥仅本地</span>
              </label>
              <label className="chk-row">
                <input type="radio" name="casrc" checked={p.useDefaultCa}
                  onChange={() => p.onDefaultCa(true)} />
                <span>内置默认共享证书（⚠️ 私钥公开，仅图省事的临时调试）</span>
              </label>
              {p.useDefaultCa && (
                <em className="muted" style={{ color: "var(--err)" }}>
                  ⚠️ 默认证书私钥是公开的：任何人都能用它伪造网站证书，装了它的机器可被他人解密 HTTPS。切勿在日常/敏感机器上使用。
                </em>
              )}
            </div>
            <div className="field">
              <span>安装证书</span>
              <div>
                <button onClick={p.onInstallCa}>安装当前 CA 到本机</button>
              </div>
              <em className="muted">
                解密 HTTPS 前需把当前 CA 装进用户根存储，浏览器/客户端才会信任解密出的证书。
                其它设备（手机等）可在浏览器打开 <b>http://&lt;本机IP&gt;:{p.port}/</b> 下载安装。
              </em>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
