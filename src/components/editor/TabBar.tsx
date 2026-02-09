import { useScriptsStore } from "@/stores/scripts.ts";
import type { MonacoEditor } from "./ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
}

export default function TabBar({ editorRef }: Props) {
  const { tabs, activeTabId, switchTab, addTab, closeTab, renameTab } =
    useScriptsStore();

  function getCurrentContent(): string {
    return editorRef.current?.getValue() ?? "";
  }

  function handleSwitch(id: string) {
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
      className="tab-bar border-b"
      style={{ borderColor: "var(--border)" }}
    >
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
  );
}
