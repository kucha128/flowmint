// 与 Tauri 后端通信的封装：invoke 命令 + 监听实时 flow 事件。
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Flow {
  flow_id: string;
  host?: string;
  method?: string;
  path?: string;
  status?: number;
  l7?: string;
  content_type?: string;
  secure?: boolean;
  resp_body_size?: number;
  parent_flow_id?: string | null;
  server?: { port: number };
  client?: { ip?: string; port: number; process_name?: string; process_pid?: number };
  opened_at_ms?: number;
}

export interface EventDetail {
  event_id: string;
  kind: string;
  direction: string;
  sequence: number;
  headers: { name: string; value: string }[];
  body: string | null;
  body_size: number;
  is_binary: boolean;
  ws_opcode?: string | null;
  tls?: { sni?: string; version?: string; decrypted: boolean } | null;
}

export interface FlowDetail {
  flow: Flow;
  events: EventDetail[];
}

export const startCapture = (
  port: number, mitm: boolean, insecure: boolean, upstream: string | null, useDefaultCa: boolean,
) => invoke<void>("start_capture", { port, mitm, insecure, upstream, useDefaultCa });

export const stopCapture = () => invoke<void>("stop_capture");

export const captureStatus = () => invoke<number | null>("capture_status");

export const searchFlows = (host: string, limit: number) =>
  invoke<Flow[]>("search_flows", { host, limit });

export const flowDetail = (flowId: string) => invoke<FlowDetail>("flow_detail", { flowId });

export const exportHar = (host?: string) => invoke<string>("export_har", { host });

export const clearStorage = () => invoke<void>("clear_storage");

export interface AppConfig {
  port: number;
  mitm: boolean;
  insecure: boolean;
  upstream: string;
  use_default_ca: boolean;
}
export const getConfig = () => invoke<AppConfig>("get_config");
export const setConfig = (config: AppConfig) => invoke<void>("set_config", { config });

export const installCa = (useDefaultCa: boolean) => invoke<string>("install_ca", { useDefaultCa });

export const regenerateCa = () => invoke<void>("regenerate_ca");

export const setSystemProxy = (port: number) => invoke<void>("set_system_proxy", { port });

export const clearSystemProxy = () => invoke<void>("clear_system_proxy");

export interface SendResult {
  status: number;
  headers: [string, string][];
  body: string;
  is_binary: boolean;
  body_size: number;
}

export const sendRequest = (
  method: string,
  url: string,
  headers: [string, string][],
  body: string,
  insecure: boolean,
) => invoke<SendResult>("send_request", { method, url, headers, body, insecure });

export const onFlow = (cb: (f: Flow) => void): Promise<UnlistenFn> =>
  listen<Flow>("flow", (e) => cb(e.payload));

// --- 断点改包 ---
export interface PausedMessage {
  id: number;
  is_response: boolean;
  method: string;
  url: string;
  status: number | null;
  headers: { name: string; value: string }[];
  body: string;
  is_binary: boolean;
}

export const setBreakpoints = (enabled: boolean, hostFilter: string | null, breakResponse: boolean) =>
  invoke<void>("set_breakpoints", { enabled, hostFilter, breakResponse });

export const resumeBreakpoint = (
  id: number,
  action: "continue" | "modify" | "drop",
  status: number | null,
  headers: [string, string][],
  body: string,
) => invoke<void>("resume_breakpoint", { id, action, status, headers, body });

export const onBreakpoint = (cb: (m: PausedMessage) => void): Promise<UnlistenFn> =>
  listen<PausedMessage>("breakpoint", (e) => cb(e.payload));
