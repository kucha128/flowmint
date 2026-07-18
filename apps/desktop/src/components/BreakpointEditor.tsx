// 断点拦截编辑器：暂停的请求/响应可编辑头/Body/状态后放行，或直接放行/丢弃。
import { useEffect, useState } from "react";
import type { PausedMessage } from "../lib/api";

type Action = "continue" | "modify" | "drop";

export function BreakpointEditor({ msg, queued, onResolve }: {
  msg: PausedMessage;
  queued: number;
  onResolve: (action: Action, status: number | null, headers: [string, string][], body: string) => void;
}) {
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [status, setStatus] = useState("");

  useEffect(() => {
    setHeaders(msg.headers.map((h) => `${h.name}: ${h.value}`).join("\n"));
    setBody(msg.is_binary ? "" : msg.body);
    setStatus(msg.status != null ? String(msg.status) : "");
  }, [msg.id]);

  return (
    <div className="inspector">
      <div className="tabs">
        <div className="tab active">
          ⏸ 断点 · {msg.is_response ? "响应" : "请求"}{queued > 1 ? ` （队列 ${queued}）` : ""}
        </div>
      </div>
      <div className="tabbody">
        <div className="kv">
          <span className="k">方法</span><span>{msg.method}</span>
          <span className="k">URL</span><span>{msg.url}</span>
          {msg.is_response && (
            <>
              <span className="k">状态</span>
              <span><input type="text" style={{ width: 80 }} value={status} onChange={(e) => setStatus(e.target.value)} /></span>
            </>
          )}
        </div>

        <div className="section-title">{msg.is_response ? "响应头" : "请求头"}（每行 Name: value）</div>
        <textarea className="composer-area" rows={7} value={headers} onChange={(e) => setHeaders(e.target.value)} />
        <div className="section-title">Body{msg.is_binary ? "（二进制，无法编辑）" : ""}</div>
        <textarea className="composer-area" rows={7} value={body} disabled={msg.is_binary} onChange={(e) => setBody(e.target.value)} />

        <div className="composer-row" style={{ marginTop: 10 }}>
          <button className="primary" onClick={() => onResolve("continue", null, [], "")}>放行</button>
          <button onClick={() => onResolve("modify", status ? Number(status) : null, parseHeaders(headers), body)}>修改并放行</button>
          <button className="danger" onClick={() => onResolve("drop", null, [], "")}>丢弃</button>
        </div>
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
