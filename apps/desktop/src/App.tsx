// 顶层组件：持有全局状态与后端交互逻辑，组合菜单栏 / 工具栏 / 会话列表 / 检查器 / 构造器 / 断点编辑器 / 对话框 / 右键菜单。
import { useEffect, useMemo, useRef, useState } from "react";
import {
  captureStatus, clearStorage, clearSystemProxy, exportHar, flowDetail, getConfig, installCa,
  onBreakpoint, onFlow, regenerateCa, resumeBreakpoint, searchFlows, setBreakpoints, setConfig,
  setSystemProxy, startCapture, stopCapture, type Flow, type FlowDetail, type PausedMessage,
} from "./lib/api";
import { curlOf, seedFromDetail, urlFromFlow, type ComposerSeed } from "./lib/format";
import { MenuBar, type MenuDef } from "./components/MenuBar";
import { Toolbar } from "./components/Toolbar";
import { StatusBar } from "./components/StatusBar";
import { SessionList } from "./components/SessionList";
import { Inspector } from "./components/Inspector";
import { Composer } from "./components/Composer";
import { BreakpointEditor } from "./components/BreakpointEditor";
import { ContextMenu, type CtxState } from "./components/ContextMenu";
import { AboutDialog, SettingsDialog } from "./components/Dialogs";

export default function App() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  const [filter, setFilter] = useState("");
  const [port, setPort] = useState(8888);
  const [running, setRunning] = useState<number | null>(null);
  const [mitm, setMitm] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [upstream, setUpstream] = useState("");
  const [useDefaultCa, setUseDefaultCa] = useState(true);
  const [sysProxy, setSysProxy] = useState(false);
  const [bpEnabled, setBpEnabled] = useState(false);
  const [pausedQueue, setPausedQueue] = useState<PausedMessage[]>([]);
  const [banner, setBanner] = useState("");
  const [mode, setMode] = useState<"inspect" | "compose">("inspect");
  const [seed, setSeed] = useState<ComposerSeed | null>(null);
  const [listWidth, setListWidth] = useState(640);
  const [modal, setModal] = useState<null | "about" | "settings">(null);
  const [ctx, setCtx] = useState<CtxState | null>(null);
  const seen = useRef<Set<string>>(new Set());

  useEffect(() => {
    // 从运行目录的配置文件恢复设置。
    getConfig().then((c) => {
      setPort(c.port); setMitm(c.mitm); setInsecure(c.insecure);
      setUpstream(c.upstream); setUseDefaultCa(c.use_default_ca);
    }).catch(() => {});
    captureStatus().then(setRunning).catch(() => {});
    searchFlows("", 2000).then((fs) => {
      seen.current = new Set(fs.map((f) => f.flow_id));
      setFlows(fs.slice().reverse());
    }).catch(() => {});

    const unlisteners: (() => void)[] = [];
    onFlow((f) => {
      setFlows((prev) => {
        if (seen.current.has(f.flow_id)) return prev.map((x) => (x.flow_id === f.flow_id ? f : x));
        seen.current.add(f.flow_id);
        return [f, ...prev];
      });
    }).then((u) => unlisteners.push(u));
    onBreakpoint((m) => setPausedQueue((q) => [...q, m])).then((u) => unlisteners.push(u));
    return () => unlisteners.forEach((u) => u());
  }, []);

  useEffect(() => {
    if (!sel) { setDetail(null); return; }
    flowDetail(sel).then(setDetail).catch((e) => setBanner(String(e)));
  }, [sel]);

  // 屏蔽 webview 默认右键菜单（刷新/另存为…）；会话列表用自绘的上下文菜单。
  useEffect(() => {
    const block = (e: MouseEvent) => e.preventDefault();
    document.addEventListener("contextmenu", block);
    return () => document.removeEventListener("contextmenu", block);
  }, []);

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return flows;
    return flows.filter((f) =>
      (f.host || "").toLowerCase().includes(q) || (f.path || "").toLowerCase().includes(q));
  }, [flows, filter]);

  // 用当前设置启动/重启代理（start_capture 会先中止旧任务再启新的）。
  const beginCapture = (m = mitm, ins = insecure, up = upstream, dca = useDefaultCa) =>
    startCapture(port, m, ins, up.trim() || null, dca);

  async function toggleCapture() {
    try {
      if (running != null) {
        await stopCapture();
        if (sysProxy) { try { await clearSystemProxy(); } catch { /* ignore */ } setSysProxy(false); }
        setRunning(null);
        setBanner("已停止抓包" + (sysProxy ? "，系统代理已还原" : ""));
      } else {
        await beginCapture();
        setRunning(port);
        setBanner(`抓包中 · 证书下载页 http://127.0.0.1:${port}/`);
      }
    } catch (e) { setBanner(String(e)); }
  }

  // 把设置持久化到运行目录的配置文件。
  const persist = (cfg: { port: number; mitm: boolean; insecure: boolean; upstream: string; use_default_ca: boolean }) =>
    setConfig(cfg).catch(() => {});

  // 以下开关随时可改；抓包中改 MITM/上游代理/证书会重启代理即时生效，并持久化。
  async function changeMitm(v: boolean) {
    setMitm(v);
    persist({ port, mitm: v, insecure, upstream, use_default_ca: useDefaultCa });
    if (running != null) {
      try { await beginCapture(v, insecure, upstream); setBanner(v ? "已开启 HTTPS 解密（代理已重启）" : "已关闭 MITM（代理已重启）"); }
      catch (e) { setBanner(String(e)); }
    }
  }
  async function changeInsecure(v: boolean) {
    setInsecure(v);
    persist({ port, mitm, insecure: v, upstream, use_default_ca: useDefaultCa });
    if (running != null) { try { await beginCapture(mitm, v, upstream); } catch (e) { setBanner(String(e)); } }
  }
  // 切换「默认共享 CA / 本机生成 CA」。
  async function changeDefaultCa(v: boolean) {
    setUseDefaultCa(v);
    persist({ port, mitm, insecure, upstream, use_default_ca: v });
    if (running != null) {
      try { await beginCapture(mitm, insecure, upstream, v); setBanner(v ? "已切到默认共享证书（代理已重启）" : "已切到本机生成证书（代理已重启）"); }
      catch (e) { setBanner(String(e)); }
    }
  }
  // 从设置对话框保存：更新端口/上游并持久化，抓包中则重启生效。
  async function applyUpstream(up: string) {
    setUpstream(up);
    persist({ port, mitm, insecure, upstream: up, use_default_ca: useDefaultCa });
    if (running != null) {
      try { await beginCapture(mitm, insecure, up); setBanner("设置已应用（代理已重启）"); }
      catch (e) { setBanner(String(e)); }
    }
  }
  async function changeSysProxy(v: boolean) {
    try {
      if (v) {
        await setSystemProxy(running ?? port);
        setBanner(running != null ? "系统代理已指向 FlowMint" : "系统代理已设置（注意：未抓包时该端口无监听）");
      } else {
        await clearSystemProxy();
        setBanner("系统代理已还原");
      }
      setSysProxy(v);
    } catch (e) { setBanner("系统代理操作失败: " + e); }
  }

  function toggleBreakpoints(v: boolean) {
    setBpEnabled(v);
    setBreakpoints(v, filter.trim() || null, true).catch((e) => setBanner(String(e)));
    setBanner(v ? "断点已开启（拦截请求与响应；用过滤框限定范围）" : "断点已关闭");
  }

  function resolvePaused(
    action: "continue" | "modify" | "drop",
    status: number | null,
    headers: [string, string][],
    body: string,
  ) {
    const m = pausedQueue[0];
    if (!m) return;
    resumeBreakpoint(m.id, action, status, headers, body).catch((e) => setBanner(String(e)));
    setPausedQueue((q) => q.slice(1));
  }

  function clearList() { seen.current = new Set(); setFlows([]); setSel(null); setDetail(null); }
  function clearStorageAll() {
    clearStorage()
      .then(() => { clearList(); setBanner("已清空存储（磁盘上的抓包数据已删除）"); })
      .catch((e) => setBanner(String(e)));
  }
  function replayCurrent() { if (detail) { setSeed(seedFromDetail(detail)); setMode("compose"); } }
  // 证书区两个动作：都切换到对应证书并安装到本机。
  async function useDefaultCert() {
    await changeDefaultCa(true);
    installCa(true).then((m) => setBanner("已使用默认证书并安装 · " + m)).catch((e) => setBanner("安装证书失败: " + e));
  }
  async function createNewCert() {
    try {
      await regenerateCa();
      await changeDefaultCa(false);
      const m = await installCa(false);
      setBanner("已创建新证书并安装 · " + m);
    } catch (e) { setBanner("创建证书失败: " + e); }
  }
  function doExportHar() { exportHar(filter || undefined).then((p) => setBanner("HAR → " + p)).catch((e) => setBanner(String(e))); }

  // --- 右键菜单动作 ---
  async function copyText(t: string, note: string) {
    try { await navigator.clipboard.writeText(t); setBanner(note); } catch (e) { setBanner(String(e)); }
  }
  async function replayFlow(f: Flow) {
    try { const d = await flowDetail(f.flow_id); setSeed(seedFromDetail(d)); setMode("compose"); }
    catch (e) { setBanner(String(e)); }
  }
  function removeFlow(f: Flow) {
    seen.current.delete(f.flow_id);
    setFlows((prev) => prev.filter((x) => x.flow_id !== f.flow_id));
    if (sel === f.flow_id) { setSel(null); setDetail(null); }
  }
  function openContext(f: Flow, x: number, y: number) {
    setCtx({ x, y, items: [
      { label: "复制 URL", onClick: () => copyText(urlFromFlow(f), "已复制 URL") },
      { label: "复制为 cURL", onClick: async () => { const d = await flowDetail(f.flow_id); copyText(curlOf(d), "已复制 cURL"); } },
      { label: "复制响应体", onClick: async () => {
        const d = await flowDetail(f.flow_id);
        const r = d.events.find((e) => e.kind === "HttpResponseHeaders");
        if (!r?.body || r.is_binary) { setBanner("响应体为空或二进制，未复制"); return; }
        copyText(r.body, "已复制响应体");
      } },
      { sep: true },
      { label: "重发（构造器）", onClick: () => replayFlow(f) },
      { label: "导出此主机 HAR", onClick: () => exportHar(f.host || undefined).then((p) => setBanner("HAR → " + p)).catch((e) => setBanner(String(e))) },
      { sep: true },
      { label: "从列表移除", onClick: () => removeFlow(f) },
    ] });
  }

  function startDrag(e: React.MouseEvent) {
    e.preventDefault();
    const onMove = (ev: MouseEvent) =>
      setListWidth(Math.max(340, Math.min(ev.clientX, window.innerWidth - 380)));
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }

  const menus: MenuDef[] = [
    { title: "文件", items: [
      { label: "导出 HAR", onClick: doExportHar },
      { label: "清空列表（仅界面）", onClick: clearList },
      { label: "清空存储（删除磁盘数据）", onClick: clearStorageAll },
    ] },
    { title: "捕获", items: [
      { label: running != null ? "停止抓包" : "开始抓包", onClick: toggleCapture },
      { label: `系统代理：${sysProxy ? "开" : "关"}`, onClick: () => changeSysProxy(!sysProxy) },
      { sep: true },
      { label: `${bpEnabled ? "关闭" : "开启"}断点`, onClick: () => toggleBreakpoints(!bpEnabled) },
    ] },
    { title: "工具", items: [
      { label: "请求构造器", onClick: () => { setSeed(null); setMode("compose"); } },
      { label: "设置…", onClick: () => setModal("settings") },
    ] },
    { title: "帮助", items: [
      { label: "关于 FlowMint Studio", onClick: () => setModal("about") },
    ] },
  ];

  return (
    <div className="app">
      <MenuBar menus={menus} />
      <Toolbar
        running={running}
        breakpoints={bpEnabled} onToggleBreakpoints={toggleBreakpoints}
        onToggleCapture={toggleCapture} onCompose={() => { setSeed(null); setMode("compose"); }}
        onExportHar={doExportHar} onClear={clearList}
      />
      <div className="split" style={{ gridTemplateColumns: `${listWidth}px 5px 1fr` }}>
        <SessionList flows={shown} total={flows.length} sel={sel} onSel={setSel}
          filter={filter} setFilter={setFilter} onContext={openContext} />
        <div className="divider" onMouseDown={startDrag} />
        {pausedQueue.length > 0
          ? <BreakpointEditor msg={pausedQueue[0]} queued={pausedQueue.length} onResolve={resolvePaused} />
          : mode === "compose"
            ? <Composer seed={seed} onBack={() => setMode("inspect")} />
            : <Inspector detail={detail} onReplay={replayCurrent} />}
      </div>
      <StatusBar
        sysProxy={sysProxy} onToggleSysProxy={changeSysProxy}
        running={running} mitm={mitm} upstream={upstream}
        flowCount={flows.length} banner={banner}
      />

      {ctx && <ContextMenu menu={ctx} onClose={() => setCtx(null)} />}
      {modal === "about" && <AboutDialog onClose={() => setModal(null)} />}
      {modal === "settings" && (
        <SettingsDialog
          onClose={() => setModal(null)} running={running}
          port={port} setPort={setPort}
          mitm={mitm} onMitm={changeMitm} insecure={insecure} onInsecure={changeInsecure}
          upstream={upstream} onSave={applyUpstream}
          useDefaultCa={useDefaultCa} onUseDefault={useDefaultCert} onCreateNew={createNewCert}
        />
      )}
    </div>
  );
}
