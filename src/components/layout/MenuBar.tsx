import { useState, useRef, useEffect } from "react";
import { TEMPLATES } from "@/lib/templates.ts";
import { importFile, exportFile } from "@/lib/fileIO.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useThemeStore } from "@/stores/theme.ts";
import { useConsoleStore } from "@/stores/console.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import type { MonacoEditor } from "@/components/editor/ScriptEditor.tsx";

interface MenuItem {
  label: string;
  action?: () => void;
  shortcut?: string;
  separator?: boolean;
  disabled?: boolean;
  submenu?: MenuItem[];
}

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
  onSave: () => void;
}

export default function MenuBar({ editorRef, onSave }: Props) {
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const barRef = useRef<HTMLDivElement>(null);

  const { syncCurrentTab, addTab, openInNewTab, getActiveTab } =
    useScriptsStore();
  const {
    sessionActive,
    scriptActive,
    runScript,
    unloadScript,
    scriptRuntime,
    setScriptRuntime,
  } = useSessionStore();
  const { toggle: toggleTheme } = useThemeStore();
  const { toggleSidePanel, toggleBottomPanel, setCommandPaletteOpen, setAboutOpen, setWelcomeOpen } =
    useLayoutStore();

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (barRef.current && !barRef.current.contains(e.target as Node)) {
        setOpenMenu(null);
      }
    }
    if (openMenu) {
      document.addEventListener("mousedown", handleClickOutside);
      return () =>
        document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [openMenu]);

  function close() {
    setOpenMenu(null);
  }

  function handleImport() {
    close();
    importFile((text) => {
      editorRef.current?.setValue(text);
      syncCurrentTab(text);
    });
  }

  function handleExport() {
    close();
    const content = editorRef.current?.getValue() ?? "";
    if (!content.trim()) return;
    const tab = getActiveTab();
    const name = tab ? tab.name : "script";
    exportFile(content, `${name.replace(/[^a-zA-Z0-9_-]/g, "_")}.js`);
  }

  function handleSaveToLibrary() {
    close();
    onSave();
  }

  const templateItems: MenuItem[] = Object.entries(TEMPLATES).map(
    ([key, t]) => ({
      label: t.label,
      action: () => {
        close();
        const code = TEMPLATES[key].code;
        const getCurrentContent = () => editorRef.current?.getValue() ?? "";
        openInNewTab(t.label, code, getCurrentContent);
        editorRef.current?.setValue(code);
      },
    }),
  );

  const menus: Record<string, MenuItem[]> = {
    File: [
      {
        label: "New Tab",
        shortcut: "Ctrl+T",
        action: () => {
          close();
          addTab(() => editorRef.current?.getValue() ?? "");
          editorRef.current?.setValue("");
        },
      },
      { label: "", separator: true },
      { label: "Open File...", shortcut: "Ctrl+O", action: handleImport },
      {
        label: "Save to Library",
        shortcut: "Ctrl+S",
        action: handleSaveToLibrary,
      },
      { label: "Export as .js", action: handleExport },
      { label: "", separator: true },
      {
        label: "Copy to Clipboard",
        action: () => {
          close();
          const val = editorRef.current?.getValue() ?? "";
          navigator.clipboard.writeText(val);
        },
      },
    ],
    Script: [
      {
        label: scriptActive ? "Re-run Script" : "Run Script",
        shortcut: "Ctrl+Enter",
        disabled: !sessionActive,
        action: () => {
          close();
          const source = editorRef.current?.getValue() ?? "";
          runScript(source);
        },
      },
      {
        label: "Unload Script",
        disabled: !scriptActive,
        action: () => {
          close();
          unloadScript();
        },
      },
      { label: "", separator: true },
      {
        label: "Runtime",
        submenu: (["default", "qjs", "v8"] as const).map((rt) => ({
          label: `${rt === scriptRuntime ? "\u2713 " : ""}${rt === "default" ? "Default" : rt.toUpperCase()}`,
          action: () => {
            close();
            setScriptRuntime(rt);
          },
        })),
      },
      { label: "", separator: true },
      { label: "Templates", submenu: templateItems },
    ],
    View: [
      {
        label: "Command Palette",
        shortcut: "Ctrl+P",
        action: () => {
          close();
          setCommandPaletteOpen(true);
        },
      },
      { label: "", separator: true },
      {
        label: "Toggle Side Panel",
        shortcut: "Ctrl+B",
        action: () => {
          close();
          toggleSidePanel();
        },
      },
      {
        label: "Toggle Console",
        shortcut: "Ctrl+`",
        action: () => {
          close();
          toggleBottomPanel();
        },
      },
      { label: "", separator: true },
      {
        label: "Toggle Theme",
        action: () => {
          close();
          toggleTheme();
        },
      },
      { label: "", separator: true },
      {
        label: "Clear Console",
        shortcut: "Ctrl+Shift+K",
        action: () => {
          close();
          useConsoleStore.getState().clear();
        },
      },
    ],
    Help: [
      {
        label: "Welcome",
        action: () => {
          close();
          setWelcomeOpen(true);
        },
      },
      { label: "", separator: true },
      {
        label: "About reFrida",
        action: () => {
          close();
          setAboutOpen(true);
        },
      },
    ],
  };

  return (
    <div ref={barRef} className="flex items-center relative menu-bar">
      {Object.entries(menus).map(([label, items]) => (
        <div key={label} className="relative">
          <button
            className="menu-bar-item"
            style={{
              background:
                openMenu === label ? "var(--hover-bg)" : "transparent",
              color:
                openMenu === label
                  ? "var(--text-primary)"
                  : "var(--text-secondary)",
            }}
            onMouseDown={() =>
              setOpenMenu(openMenu === label ? null : label)
            }
            onMouseEnter={() => openMenu && setOpenMenu(label)}
          >
            {label}
          </button>
          {openMenu === label && (
            <MenuDropdown items={items} onClose={close} />
          )}
        </div>
      ))}
    </div>
  );
}

function MenuDropdown({
  items,
  onClose,
}: {
  items: MenuItem[];
  onClose: () => void;
}) {
  return (
    <div className="menu-dropdown">
      {items.map((item, i) => {
        if (item.separator) {
          return (
            <div
              key={i}
              className="my-0.5 border-t"
              style={{ borderColor: "var(--border)" }}
            />
          );
        }
        if (item.submenu) {
          return (
            <SubMenu key={i} label={item.label} items={item.submenu} onClose={onClose} />
          );
        }
        return (
          <button
            key={i}
            className="menu-dropdown-item"
            disabled={item.disabled}
            onClick={() => item.action?.()}
          >
            <span className="flex-1">{item.label}</span>
            {item.shortcut && (
              <span className="menu-shortcut">{item.shortcut}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

function SubMenu({
  label,
  items,
  onClose,
}: {
  label: string;
  items: MenuItem[];
  onClose: () => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div
      className="relative"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button className="menu-dropdown-item">
        <span className="flex-1">{label}</span>
        <i className="fa-solid fa-chevron-right text-[8px]" style={{ color: "var(--text-muted)" }} />
      </button>
      {open && (
        <div className="menu-dropdown submenu-right">
          {items.map((item, i) => (
            <button
              key={i}
              className="menu-dropdown-item"
              onClick={() => {
                item.action?.();
                onClose();
              }}
            >
              <span className="flex-1">{item.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
