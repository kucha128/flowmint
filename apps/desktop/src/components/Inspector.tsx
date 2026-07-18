// 右侧检查器：按标签展示所选 flow 的概览/请求/响应/原始/Hex/TLS，
// WebSocket 流则展示帧时间线。子视图都很小，内聚在本文件（同属"检查一条 flow"）。
import { useEffect, useState } from "react";
import type { EventDetail, Flow, FlowDetail } from "../lib/api";
import { bytesOf, curlOf, hexDump, human, imageDataUrl, prettyBody, statusClass } from "../lib/format";

export function Inspector({ detail, onReplay }: { detail: FlowDetail | null; onReplay: () => void }) {
  const isWs = detail?.flow.l7 === "websocket";
  const tabs = isWs
    ? ["概览", "帧"]
    : ["概览", "请求", "响应", "原始", "Hex"];
  const [tab, setTab] = useState("概览");
  useEffect(() => setTab("概览"), [detail?.flow.flow_id]);

  if (!detail) return <div className="inspector"><div className="empty">选择一条 flow 查看详情。</div></div>;

  const req = detail.events.find((e) => e.kind === "HttpRequestHeaders");
  const resp = detail.events.find((e) => e.kind === "HttpResponseHeaders");
  const frames = detail.events.filter((e) => e.kind === "WebSocketFrame");
  const f = detail.flow;

  return (
    <div className="inspector">
      <div className="tabs">
        {tabs.map((t) => (
          <div key={t} className={"tab" + (tab === t ? " active" : "")} onClick={() => setTab(t)}>{t}</div>
        ))}
        <span style={{ flex: 1 }} />
        <div className="tab" onClick={onReplay} title="用此请求填充构造器">↻ 重放</div>
        <div className="tab" onClick={() => navigator.clipboard.writeText(curlOf(detail))} title="复制为 cURL 命令">复制 cURL</div>
      </div>
      <div className="tabbody">
        {tab === "概览" && <Overview detail={detail} />}
        {tab === "请求" && <MessageView ev={req} title="请求" />}
        {tab === "响应" && <MessageView ev={resp} title="响应" />}
        {tab === "原始" && <RawView flow={f} req={req} resp={resp} />}
        {tab === "Hex" && <HexView ev={resp || req} />}
        {tab === "帧" && <Frames frames={frames} />}
      </div>
    </div>
  );
}

function Overview({ detail }: { detail: FlowDetail }) {
  const f = detail.flow;
  const decrypted = detail.events.some((e) => e.tls?.decrypted);
  return (
    <div className="kv">
      <span className="k">Flow</span><span>{f.flow_id}</span>
      <span className="k">方法</span><span>{f.method || "-"}</span>
      <span className="k">主机</span><span>{f.host || "-"}</span>
      <span className="k">路径</span><span>{f.path || "-"}</span>
      <span className="k">状态</span><span className={statusClass(f.status)}>{f.status ?? "-"}</span>
      <span className="k">协议</span><span>{f.l7 || "-"}{decrypted ? "  (TLS 已解密)" : ""}</span>
      <span className="k">服务端</span><span>{f.host}:{f.server?.port}</span>
      <span className="k">客户端</span><span>{f.client?.ip}:{f.client?.port}</span>
    </div>
  );
}

function MessageView({ ev, title }: { ev?: EventDetail; title: string }) {
  if (!ev) return <div className="empty">无{title}。</div>;
  return (
    <div>
      <div className="section-title">{title}头</div>
      {(ev.headers || []).map((h, i) => (
        <div className="hdr" key={i}><span className="n">{h.name}</span>: {h.value}</div>
      ))}
      <div className="section-title">Body {ev.body_size ? `(${human(ev.body_size)})` : "(空)"}</div>
      <BodyView ev={ev} />
    </div>
  );
}

/** Body 展示：图片走内联预览，其余文本/JSON 美化，二进制提示看 Hex。 */
function BodyView({ ev }: { ev: EventDetail }) {
  const img = imageDataUrl(ev);
  if (img) return <img className="body-img" src={img} alt="响应图片预览" />;
  if (!ev.body) return <div className="empty">无 body</div>;
  return <pre className="body">{prettyBody(ev)}</pre>;
}

function RawView({ flow, req, resp }: { flow: Flow; req?: EventDetail; resp?: EventDetail }) {
  const rawReq = req
    ? `${flow.method} ${flow.path} HTTP/1.1\n` +
      (req.headers || []).map((h) => `${h.name}: ${h.value}`).join("\n") +
      (req.body && !req.is_binary ? `\n\n${req.body}` : "")
    : "(无请求)";
  const rawResp = resp
    ? `HTTP/1.1 ${flow.status ?? ""}\n` +
      (resp.headers || []).map((h) => `${h.name}: ${h.value}`).join("\n") +
      (resp.body && !resp.is_binary ? `\n\n${resp.body}` : "")
    : "(无响应)";
  return (
    <div>
      <div className="section-title">原始请求</div>
      <pre className="body">{rawReq}</pre>
      <div className="section-title">原始响应</div>
      <pre className="body">{rawResp}</pre>
    </div>
  );
}

function HexView({ ev }: { ev?: EventDetail }) {
  if (!ev || !ev.body) return <div className="empty">无 body</div>;
  return <pre className="body hex">{hexDump(bytesOf(ev))}</pre>;
}

/** WebSocket 帧时间线：上方列出每帧（方向/类型/长度），点选后下方按字符串或 Hex 展示 payload。 */
function Frames({ frames }: { frames: EventDetail[] }) {
  const [sel, setSel] = useState(0);
  const [mode, setMode] = useState<"str" | "hex">("str");
  if (frames.length === 0) return <div className="empty">无帧</div>;
  const cur = frames[Math.min(sel, frames.length - 1)];
  return (
    <div className="ws-frames">
      <div className="frame-list">
        {frames.map((fr, i) => {
          const out = fr.direction === "ClientToServer";
          return (
            <div className={"frame-row" + (i === sel ? " sel" : "")} key={i} onClick={() => setSel(i)}>
              <span className={out ? "dir-cs" : "dir-sc"}>{out ? "▲ 发送" : "▼ 接收"}</span>
              <span className="fr-op">{fr.ws_opcode || "frame"}</span>
              <span className="fr-len">{human(fr.body_size)}</span>
            </div>
          );
        })}
      </div>
      <div className="frame-detail">
        <div className="frame-detail-head">
          <span>{cur.ws_opcode || "frame"} · {cur.body_size} 字节</span>
          <span style={{ flex: 1 }} />
          <div className={"tab" + (mode === "str" ? " active" : "")} onClick={() => setMode("str")}>字符串</div>
          <div className={"tab" + (mode === "hex" ? " active" : "")} onClick={() => setMode("hex")}>Hex</div>
        </div>
        <pre className={"body" + (mode === "hex" ? " hex" : "")}>{framePayload(cur, mode)}</pre>
      </div>
    </div>
  );
}

/** 单帧 payload：Hex 走十六进制转储；字符串视图下二进制帧提示切 Hex。 */
function framePayload(ev: EventDetail, mode: "str" | "hex"): string {
  if (!ev.body) return "(空帧，无 payload)";
  if (mode === "hex") return hexDump(bytesOf(ev));
  if (ev.is_binary) return "(二进制帧，切到 Hex 查看)";
  return ev.body;
}

