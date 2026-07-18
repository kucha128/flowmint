// 底部状态栏（对标 Fiddler）：左下角是系统代理开关，中间显示状态提示，右侧显示抓包状态与条数。
interface Props {
  sysProxy: boolean;
  onToggleSysProxy: (v: boolean) => void;
  running: number | null;
  mitm: boolean;
  upstream: string;
  flowCount: number;
  banner: string;
  caInstalled: boolean;
  onCert: () => void;
}

export function StatusBar(p: Props) {
  return (
    <div className="statusbar">
      <button className={"sb-toggle" + (p.sysProxy ? " on" : "")}
        onClick={() => p.onToggleSysProxy(!p.sysProxy)}
        title="把 Windows 系统代理指向 FlowMint（再次点击关闭）">
        <span className={"dot " + (p.sysProxy ? "on" : "off")} />
        系统代理：{p.sysProxy ? "开" : "关"}
      </button>

      <button className="sb-toggle" onClick={p.onCert} title="证书设置">
        <span className={"dot " + (p.caInstalled ? "on" : "off")} />
        证书：{p.caInstalled ? "已安装" : "未安装"}
      </button>

      <span className="sb-msg" title={p.banner}>{p.banner}</span>

      <span className="grow" />

      <span className="sb-info">
        <span className={"dot " + (p.running != null ? "on" : "off")} />
        {p.running != null
          ? `抓包中 127.0.0.1:${p.running}${p.mitm ? " · MITM" : ""}${p.upstream.trim() ? " → " + p.upstream.trim() : ""}`
          : "空闲"}
      </span>
      <span className="sb-info">{p.flowCount} 条</span>
    </div>
  );
}
