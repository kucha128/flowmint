// 通用右键上下文菜单：在光标处弹出一列可点条目，点击外部/滚动/Esc 关闭。
import { useEffect } from "react";

export interface CtxItem {
  label?: string;
  onClick?: () => void;
  sep?: boolean;
}
export interface CtxState {
  x: number;
  y: number;
  items: CtxItem[];
}

export function ContextMenu({ menu, onClose }: { menu: CtxState; onClose: () => void }) {
  useEffect(() => {
    const close = () => onClose();
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  // 避免菜单超出窗口右/下边界。
  const left = Math.min(menu.x, window.innerWidth - 190);
  const top = Math.min(menu.y, window.innerHeight - menu.items.length * 30 - 10);

  return (
    <div className="ctx-menu" style={{ left, top }} onClick={(e) => e.stopPropagation()}>
      {menu.items.map((it, i) =>
        it.sep ? (
          <div key={i} className="ctx-sep" />
        ) : (
          <div key={i} className="ctx-item"
            onClick={() => { it.onClick?.(); onClose(); }}>
            {it.label}
          </div>
        ),
      )}
    </div>
  );
}
