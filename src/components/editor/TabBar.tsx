import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import type { MonacoEditor } from "./ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
  onRun: () => void;
}

export default function TabBar({ editorRef, onRun }: Props) {
  const { tabs, activeTabId, switchTab, addTab, closeTab, renameTab } =
    useScriptsStore();
  const { sessionActive, scriptActive, unloadScript } = useSessionStore();

  function getCurrentContent(): string {
    return editorRef.current?.getValue() ?? "";
  }

  function handleSwitch(id: string) {
    if (scriptActive) {
      unloadScript();
    }
    switchTab(id, getCurrentContent);
    const tab = useScriptsStore.getState().tabs.find((t) => t.id === id);
    if (tab && editorRef.current) {
      editorRef.current.setValue(tab.content);
    }
  }

  function handleAdd() {
    addTab(getCurrentContent);
    if (editorRef.current) {
      editorRef.current.setValue("");
    }
  }

  function handleClose(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    const content = closeTab(id);
    if (content !== null && editorRef.current) {
      editorRef.current.setValue(content);
    }
  }

  function handleRename(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    const tab = tabs.find((t) => t.id === id);
    if (!tab) return;
    const name = prompt("Tab name:", tab.name);
    if (name) renameTab(id, name);
  }

  return (
    <div
      className="flex items-center border-b"
      style={{ borderColor: "var(--border)" }}
    >
      <div className="tab-bar flex-1">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={`tab-item ${tab.id === activeTabId ? "active" : ""}`}
            onClick={() => handleSwitch(tab.id)}
            onDoubleClick={(e) => handleRename(e, tab.id)}
          >
            <span>{tab.name}</span>
            {tabs.length > 1 && (
              <span
                className="tab-close"
                onClick={(e) => handleClose(e, tab.id)}
              >
                x
              </span>
            )}
          </div>
        ))}
        <div
          className="tab-item"
          onClick={handleAdd}
          style={{ color: "var(--text-muted)" }}
        >
          +
        </div>
      </div>

      <div className="flex items-center gap-1 px-2 shrink-0">
        <button
          onClick={onRun}
          disabled={!sessionActive}
          className="titlebar-btn disabled:opacity-30"
          style={{ color: scriptActive ? "#d97706" : "#22c55e" }}
          title={scriptActive ? "Re-run (Ctrl+Enter)" : "Run (Ctrl+Enter)"}
        >
          <i
            className={`fa-solid ${scriptActive ? "fa-rotate-right" : "fa-play"}`}
            style={{ fontSize: 12 }}
          />
        </button>

        {scriptActive && (
          <button
            onClick={unloadScript}
            className="titlebar-btn"
            style={{ color: "#ef4444" }}
            title="Stop Script"
          >
            <i className="fa-solid fa-stop" style={{ fontSize: 11 }} />
          </button>
        )}
      </div>
    </div>
  );
}
