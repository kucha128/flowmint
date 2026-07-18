// 请求构造器 / 重放（对标 Fiddler Composer）：编辑 method/url/头/Body 后发送，看响应。
import { useEffect, useState } from "react";
import { sendRequest, type SendResult } from "../lib/api";
import type { ComposerSeed } from "../lib/format";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export function Composer({ seed, onBack }: { seed: ComposerSeed | null; onBack: () => void }) {
  const [method, setMethod] = useState(seed?.method || "GET");
  const [url, setUrl] = useState(seed?.url || "");
  const [headers, setHeaders] = useState(seed?.headers || "");
  const [body, setBody] = useState(seed?.body || "");
  const [insecure, setInsecure] = useState(false);
  const [resp, setResp] = useState<SendResult | null>(null);
  const [err, setErr] = useState("");
  const [sending, setSending] = useState(false);

  useEffect(() => {
    if (seed) {
      setMethod(seed.method || "GET");
      setUrl(seed.url);
      setHeaders(seed.headers);
      setBody(seed.body);
      setResp(null);
      setErr("");
    }
  }, [seed]);

  async function send() {
    setErr("");
    setResp(null);
    setSending(true);
    try {
      setResp(await sendRequest(method, url, parseHeaders(headers), body, insecure));
    } catch (e) {
      setErr(String(e));
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="inspector">
      <div className="tabs">
        <div className="tab" onClick={onBack}>← 返回</div>
        <div className="tab active">构造器 / 重放</div>
      </div>
      <div className="tabbody">
        <div className="composer-row">
          <select value={method} onChange={(e) => setMethod(e.target.value)}>
            {METHODS.map((m) => <option key={m}>{m}</option>)}
          </select>
          <input type="text" style={{ flex: 1 }} placeholder="http(s)://host/path"
            value={url} onChange={(e) => setUrl(e.target.value)} />
          <button className="primary" onClick={send} disabled={sending || !url}>
            {sending ? "发送中…" : "发送"}
          </button>
        </div>
        <label className="chk" style={{ margin: "6px 0" }}>
          <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
          不校验上游 TLS（测试自签名）
        </label>

        <div className="section-title">请求头（每行 Name: value）</div>
        <textarea className="composer-area" rows={6} value={headers} onChange={(e) => setHeaders(e.target.value)} />
        <div className="section-title">请求 Body</div>
        <textarea className="composer-area" rows={6} value={body} onChange={(e) => setBody(e.target.value)} />

        {err && <div className="composer-err">错误：{err}</div>}
        {resp && (
          <div>
            <div className="section-title">响应 · 状态 {resp.status} · {resp.body_size} 字节</div>
            {resp.headers.map(([k, v], i) => (
              <div className="hdr" key={i}><span className="n">{k}</span>: {v}</div>
            ))}
            <div className="section-title">响应 Body</div>
            <pre className="body">{resp.is_binary ? "[二进制响应]" : prettyJson(resp.body)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

function parseHeaders(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const line of text.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) out.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return out;
}

function prettyJson(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}
