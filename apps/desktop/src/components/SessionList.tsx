// 左侧会话列表：实时刷新的 flow 列表，多列（方法/状态/协议/主机/URL/类型/大小）+ 过滤 + 右键菜单。
import type { Flow } from "../lib/api";
import { human, statusClass } from "../lib/format";

/** content-type 简写：去掉参数、取子类型。 */
function shortType(ct?: string): string {
  if (!ct) return "";
  const main = ct.split(";")[0].trim();
  const slash = main.indexOf("/");
  return slash >= 0 ? main.slice(slash + 1) : main;
}

/** 从 flow 推断展示用的协议方案（清晰区分 http/https）。 */
function schemeOf(f: Flow): string {
  if (f.l7 === "websocket") return f.secure ? "WSS" : "WS";
  if (f.l7 === "connect" || f.l7 === "tls") return "HTTPS"; // 未解密的加密隧道
  return f.secure ? "HTTPS" : "HTTP";
}

interface Props {
  flows: Flow[];
  total: number;
  sel: string | null;
  onSel: (id: string) => void;
  filter: string;
  setFilter: (s: string) => void;
  onContext: (f: Flow, x: number, y: number) => void;
}

export function SessionList(props: Props) {
  return (
    <div className="sessions">
      <div className="filter">
        <input type="text" placeholder="过滤 主机 / 路径…" value={props.filter}
          onChange={(e) => props.setFilter(e.target.value)} />
        <span style={{ color: "var(--muted)", fontSize: 12, alignSelf: "center" }}>
          {props.flows.length}/{props.total}
        </span>
      </div>
      <div className="grid-head">
        <div>#</div><div>方法</div><div>状态</div><div>协议</div><div>主机</div><div>URL</div><div>类型</div><div>大小</div><div>进程</div>
      </div>
      <div className="rows">
        {props.flows.map((f, i) => {
          const scheme = schemeOf(f);
          return (
            <div key={f.flow_id} className={"grid-row" + (props.sel === f.flow_id ? " sel" : "")}
              onClick={() => props.onSel(f.flow_id)}
              onContextMenu={(e) => { e.preventDefault(); props.onSel(f.flow_id); props.onContext(f, e.clientX, e.clientY); }}>
              <div className="idx">{props.flows.length - i}</div>
              <div className="m">{f.method || "-"}</div>
              <div className={statusClass(f.status)}>{f.status ?? ""}</div>
              <div className={"scheme " + scheme.toLowerCase()}>{scheme}</div>
              <div className="host" title={f.host || ""}>{f.host || "-"}</div>
              <div className="u" title={f.path || ""}>{f.path || ""}</div>
              <div className="ct" title={f.content_type || ""}>{shortType(f.content_type)}</div>
              <div className="sz">{human(f.resp_body_size)}</div>
              <div className="proc" title={f.client?.process_pid ? `${f.client?.process_name || ""} (PID ${f.client?.process_pid})` : ""}>
                {f.client?.process_name || ""}
              </div>
            </div>
          );
        })}
        {props.flows.length === 0 && (
          <div className="empty">暂无 flow。开始抓包并让客户端走该代理。</div>
        )}
      </div>
    </div>
  );
}
