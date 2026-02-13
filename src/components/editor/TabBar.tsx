import { useState, useRef, useEffect } from "react";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import type { MonacoEditor } from "./ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
  onRun: () => void;
}

export default function TabBar({ editorRef, onRun }: Props) {
  const { tabs, activeTabId, switchTab, addTab, closeTab, renameTab } =
    useScriptsStore();
  const { sessionActive, scriptActive, unloadScript } = useSessionStore();
  const { welcomeOpen, setWelcomeOpen } = useLayoutStore();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editingId && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editingId]);

  function getCurrentContent(): string {
    return editorRef.current?.getValue() ?? "";
  }

  function handleSwitch(id: string) {
    if (welcomeOpen) setWelcomeOpen(false);
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
    if (welcomeOpen) setWelcomeOpen(false);
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

  function startRename(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    const tab = tabs.find((t) => t.id === id);
    if (!tab) return;
    setEditingId(id);
    setEditValue(tab.name);
  }

  function commitRename() {
    if (editingId && editValue.trim()) {
      renameTab(editingId, editValue.trim());
    }
    setEditingId(null);
  }

  function handleRenameKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") commitRename();
    if (e.key === "Escape") setEditingId(null);
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
            onDoubleClick={(e) => startRename(e, tab.id)}
          >
            {editingId === tab.id ? (
              <input
                ref={inputRef}
                value={editValue}
                onChange={(e) => setEditValue(e.target.value)}
                onBlur={commitRename}
                onKeyDown={handleRenameKeyDown}
                className="text-xs bg-transparent outline-none border-b w-20"
                style={{
                  color: "var(--text-primary)",
                  borderColor: "var(--accent)",
                }}
                onClick={(e) => e.stopPropagation()}
              />
            ) : (
              <span>{tab.name}</span>
            )}
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

      <div className="flex items-center gap-1.5 px-2 shrink-0">
        <button
          onClick={onRun}
          disabled={!sessionActive}
          className="flex items-center gap-1.5 text-xs font-medium px-3 py-1 rounded disabled:opacity-30"
          style={{
            color: "white",
            background: scriptActive ? "var(--accent)" : "#16a34a",
          }}
          title={scriptActive ? "Re-run (Ctrl+Enter)" : "Run (Ctrl+Enter)"}
        >
          <i
            className={`fa-solid ${scriptActive ? "fa-rotate-right" : "fa-play"}`}
            style={{ fontSize: 10 }}
          />
          {scriptActive ? "Re-run" : "Run"}
        </button>

        {scriptActive && (
          <button
            onClick={unloadScript}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1 rounded"
            style={{
              color: "#ef4444",
              border: "1px solid rgba(239, 68, 68, 0.3)",
            }}
            title="Stop Script"
          >
            <i className="fa-solid fa-stop" style={{ fontSize: 9 }} />
            Stop
          </button>
        )}
      </div>
    </div>
  );
}
