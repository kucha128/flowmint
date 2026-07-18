// 顶部菜单栏（对标 Fiddler）：下拉菜单触发常用操作。
import { useEffect, useState } from "react";

export interface MenuItemDef {
  label?: string;
  onClick?: () => void;
  disabled?: boolean;
  sep?: boolean; // 分隔线
}
export interface MenuDef {
  title: string;
  items: MenuItemDef[];
}

export function MenuBar({ menus }: { menus: MenuDef[] }) {
  const [open, setOpen] = useState<number | null>(null);

  useEffect(() => {
    const close = () => setOpen(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  return (
    <div className="menubar" onClick={(e) => e.stopPropagation()}>
      {menus.map((m, i) => (
        <div key={i} className="menu">
          <div className={"menu-title" + (open === i ? " open" : "")}
            onClick={() => setOpen(open === i ? null : i)}
            onMouseEnter={() => open !== null && setOpen(i)}>
            {m.title}
          </div>
          {open === i && (
            <div className="menu-drop">
              {m.items.map((it, j) =>
                it.sep ? (
                  <div key={j} className="menu-sep" />
                ) : (
                  <div key={j} className={"menu-item" + (it.disabled ? " disabled" : "")}
                    onClick={() => { if (!it.disabled) { it.onClick?.(); setOpen(null); } }}>
                    {it.label}
                  </div>
                ),
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
