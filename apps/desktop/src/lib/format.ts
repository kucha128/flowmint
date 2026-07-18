// 检查器用到的纯展示辅助函数：状态色、大小、Body 美化、十六进制转储、构造器 seed。
import type { EventDetail, Flow, FlowDetail } from "./api";

export interface ComposerSeed {
  method: string;
  url: string;
  headers: string; // 每行 "Name: value"
  body: string;
}

/** 从选中流量的详情拼出完整 URL（scheme + host[:port] + path）。 */
function urlOf(detail: FlowDetail): string {
  const tls = detail.events.some((e) => e.tls?.decrypted);
  const scheme = tls ? "https" : "http";
  const dp = tls ? 443 : 80;
  const port = detail.flow.server?.port;
  const host = detail.flow.host || "";
  const authority = port && port !== dp ? `${host}:${port}` : host;
  return `${scheme}://${authority}${detail.flow.path || "/"}`;
}

/** 从一条 flow（列表项，无 events）拼出完整 URL。 */
export function urlFromFlow(f: Flow): string {
  const scheme = f.secure ? "https" : "http";
  const dp = f.secure ? 443 : 80;
  const port = f.server?.port;
  const host = f.host || "";
  const authority = port && port !== dp ? `${host}:${port}` : host;
  return `${scheme}://${authority}${f.path || "/"}`;
}

/** 取事件头里的 Content-Type（小写、去参数）。 */
function contentTypeOf(ev: EventDetail): string {
  const h = (ev.headers || []).find((x) => x.name.toLowerCase() === "content-type");
  return (h?.value || "").split(";")[0].trim().toLowerCase();
}

/** 若响应体是可预览图片，返回其 data: URL，否则 null。 */
export function imageDataUrl(ev: EventDetail): string | null {
  const ct = contentTypeOf(ev);
  if (!ct.startsWith("image/") || !ev.body) return null;
  const bytes = bytesOf(ev);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return `data:${ct};base64,${btoa(bin)}`;
}

/** 用选中流量的请求预填构造器。 */
export function seedFromDetail(detail: FlowDetail): ComposerSeed {
  const req = detail.events.find((e) => e.kind === "HttpRequestHeaders");
  const headers = (req?.headers || []).map((h) => `${h.name}: ${h.value}`).join("\n");
  const body = req && !req.is_binary ? req.body || "" : "";
  return { method: detail.flow.method || "GET", url: urlOf(detail), headers, body };
}

/** 生成等价的 cURL 命令。 */
export function curlOf(detail: FlowDetail): string {
  const req = detail.events.find((e) => e.kind === "HttpRequestHeaders");
  const q = (s: string) => s.replace(/"/g, '\\"');
  let cmd = `curl -X ${detail.flow.method || "GET"} "${urlOf(detail)}"`;
  for (const h of req?.headers || []) cmd += ` -H "${q(h.name)}: ${q(h.value)}"`;
  if (req?.body && !req.is_binary) cmd += ` --data-raw "${q(req.body)}"`;
  return cmd;
}

/** HTTP 状态码 → CSS 类（按首位分组：2xx/3xx/4xx/5xx）。 */
export function statusClass(s?: number): string {
  if (!s) return "";
  return "st-" + Math.floor(s / 100);
}

/** 字节数 → 人类可读大小。 */
export function human(n?: number): string {
  if (!n) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " K";
  return (n / 1024 / 1024).toFixed(1) + " M";
}

/** Body 展示：文本优先 JSON 美化；二进制走 Hex 标签。 */
export function prettyBody(ev: EventDetail): string {
  if (ev.is_binary) return "[二进制 Body — 见 Hex 标签]";
  const b = ev.body || "";
  try {
    return JSON.stringify(JSON.parse(b), null, 2);
  } catch {
    return b;
  }
}

/** 取 Body 的原始字节：二进制时后端已给 hex 字符串，文本时用 UTF-8 编码。 */
export function bytesOf(ev: EventDetail): Uint8Array {
  if (ev.is_binary && ev.body) {
    const hex = ev.body;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  return new TextEncoder().encode(ev.body || "");
}

/** 经典十六进制转储：偏移 | 16 字节 hex | ASCII。 */
export function hexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.subarray(off, off + 16);
    const hex = Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48, " ");
    const ascii = Array.from(slice).map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(off.toString(16).padStart(8, "0") + "  " + hex + "  " + ascii);
  }
  return lines.join("\n") || "(空)";
}
