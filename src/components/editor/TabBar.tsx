import { useState, useRef, useEffect } from "react";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";
import type { MonacoEditor } from "./ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
  onRun: () => void;
}

export default function TabBar({ editorRef, onRun }: Props) {
  const { tabs, activeTabId, switchTab, addTab, closeTab, renameTab, reorderTabs } =
    useScriptsStore();
  const { sessionActive, scriptActive, busy, busyLabel, unloadScript, cancelBusy } = useSessionStore();
  const { welcomeOpen, setWelcomeOpen } = useLayoutStore();
  const isMobile = useIsMobile();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [dragId, setDragId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
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

  function handleDragStart(e: React.DragEvent, id: string) {
    setDragId(id);
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", id);
  }

  function handleDragOver(e: React.DragEvent, id: string) {
    if (!dragId || dragId === id) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    setDropTarget(id);
  }

  function handleDrop(e: React.DragEvent, id: string) {
    e.preventDefault();
    if (dragId && dragId !== id) {
      reorderTabs(dragId, id);
    }
    setDragId(null);
    setDropTarget(null);
  }

  function handleDragEnd() {
    setDragId(null);
    setDropTarget(null);
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
            style={{
              opacity: dragId === tab.id ? 0.4 : 1,
              borderLeft: dropTarget === tab.id ? "2px solid var(--accent)" : undefined,
            }}
            onClick={() => handleSwitch(tab.id)}
            onDoubleClick={(e) => startRename(e, tab.id)}
            draggable={!isMobile && editingId !== tab.id}
            onDragStart={(e) => handleDragStart(e, tab.id)}
            onDragOver={(e) => handleDragOver(e, tab.id)}
            onDrop={(e) => handleDrop(e, tab.id)}
            onDragEnd={handleDragEnd}
            onDragLeave={() => setDropTarget(null)}
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

      <div className="flex items-center gap-1 px-2 shrink-0">
        {busy ? (
          <>
            <span
              className="text-[10px] px-1"
              style={{ color: "var(--text-muted)" }}
            >
              {busyLabel}
            </span>
            <button
              onClick={cancelBusy}
              className="flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded"
              style={{
                color: "#ef4444",
                border: "1px solid rgba(239, 68, 68, 0.25)",
              }}
              title="Cancel"
            >
              <i className="fa-solid fa-xmark" style={{ fontSize: 9 }} />
              Cancel
            </button>
          </>
        ) : scriptActive ? (
          <>
            <button
              onClick={unloadScript}
              className="flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded"
              style={{
                color: "#ef4444",
                border: "1px solid rgba(239, 68, 68, 0.25)",
              }}
              title="Stop Script"
            >
              <i className="fa-solid fa-stop" style={{ fontSize: 8 }} />
              Stop
            </button>
            <button
              onClick={onRun}
              className="flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded"
              style={{
                color: "var(--accent-text)",
                border: "1px solid var(--accent)",
                background: "var(--accent-soft)",
              }}
              title="Re-run (Ctrl+Enter)"
            >
              <i className="fa-solid fa-rotate-right" style={{ fontSize: 8 }} />
              Re-run
            </button>
          </>
        ) : (
          <button
            onClick={onRun}
            disabled={!sessionActive}
            className="flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded disabled:opacity-30"
            style={{
              color: "white",
              background: "#16a34a",
            }}
            title="Run (Ctrl+Enter)"
          >
            <i className="fa-solid fa-play" style={{ fontSize: 9 }} />
            Run
          </button>
        )}
      </div>
    </div>
  );
}
