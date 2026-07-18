// 顶部工具栏（精简，对标 Fiddler）：只放主操作按钮；端口/MITM 等配置移到「设置」对话框，
// 系统代理开关移到底部状态栏。
interface Props {
  running: number | null;
  breakpoints: boolean;
  onToggleCapture: () => void;
  onToggleBreakpoints: (v: boolean) => void;
  onCompose: () => void;
  onExportHar: () => void;
  onClear: () => void;
}

export function Toolbar(p: Props) {
  return (
    <div className="toolbar">
      <div className="title">Flow<span>Mint</span> Studio</div>
      <button className={p.running != null ? "danger" : "primary"} onClick={p.onToggleCapture}>
        {p.running != null ? "■ 停止" : "▶ 开始抓包"}
      </button>
      <label className="chk" title="拦截请求/响应，暂停后可编辑再放行（配合过滤框限定范围）">
        <input type="checkbox" checked={p.breakpoints}
          onChange={(e) => p.onToggleBreakpoints(e.target.checked)} /> 断点
      </label>
      <span className="tb-sep" />
      <button onClick={p.onCompose}>请求构造器</button>
      <button onClick={p.onExportHar}>导出 HAR</button>
      <button onClick={p.onClear}>清空</button>
    </div>
  );
}
