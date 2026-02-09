import { useState, useRef, useEffect } from "react";
import { TEMPLATES } from "@/lib/templates.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import type { MonacoEditor } from "./ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
}

export default function EditorToolbar({ editorRef }: Props) {
  const [selectedTemplate, setSelectedTemplate] = useState("");
  const [copySuccess, setCopySuccess] = useState(false);
  const {
    savedScripts,
    showSavedScripts,
    setShowSavedScripts,
    saveToLibrary,
    loadFromLibrary,
    deleteFromLibrary,
    syncCurrentTab,
  } = useScriptsStore();
  const {
    sessionActive,
    scriptActive,
    scriptRuntime,
    setScriptRuntime,
    runScript,
    unloadScript,
    sessionInfoText,
  } = useSessionStore();
  const busy = false;
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node)
      ) {
        setShowSavedScripts(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [setShowSavedScripts]);

  function handleTemplateChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const name = e.target.value;
    if (!name || !TEMPLATES[name]) return;
    editorRef.current?.setValue(TEMPLATES[name].code);
    syncCurrentTab(TEMPLATES[name].code);
    setSelectedTemplate("");
  }

  function handleCopy() {
    const val = editorRef.current?.getValue() ?? "";
    navigator.clipboard.writeText(val).then(() => {
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 1500);
    });
  }

  function handleRun() {
    const source = editorRef.current?.getValue() ?? "";
    runScript(source);
  }

  function handleLoadFromLibrary(id: string) {
    const content = loadFromLibrary(id);
    if (content !== null && editorRef.current) {
      editorRef.current.setValue(content);
    }
  }

  function handleImport() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".js,.ts,.txt";
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (ev) => {
          const text = ev.target?.result as string;
          editorRef.current?.setValue(text);
          syncCurrentTab(text);
        };
        reader.readAsText(file);
      }
    };
    input.click();
  }

  function handleExport() {
    const content = editorRef.current?.getValue() ?? "";
    if (!content.trim()) return;
    const tab = useScriptsStore.getState().getActiveTab();
    const name = tab ? tab.name : "script";
    const blob = new Blob([content], { type: "text/javascript" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name.replace(/[^a-zA-Z0-9_-]/g, "_")}.js`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div
      className="flex items-center gap-1.5 px-2 py-1 border-b"
      style={{
        borderColor: "var(--border)",
        background: "var(--bg-secondary)",
      }}
    >
      <button
        onClick={handleRun}
        disabled={!sessionActive || busy}
        className={`text-xs px-2.5 py-0.5 rounded font-medium text-white ${scriptActive ? "bg-amber-600 hover:bg-amber-700" : "bg-cyan-600 hover:bg-cyan-700"} disabled:opacity-40`}
      >
        {scriptActive ? "Re-run" : "Run"}
      </button>

      {scriptActive && (
        <button
          onClick={unloadScript}
          className="text-xs px-2 py-0.5 rounded font-medium text-white bg-red-600 hover:bg-red-700"
        >
          Unload
        </button>
      )}

      {sessionActive && (
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
          {sessionInfoText}
        </span>
      )}

      <div className="flex-1" />

      <select
        value={scriptRuntime}
        onChange={(e) => setScriptRuntime(e.target.value)}
        className="text-[11px] px-1 py-0.5 rounded border outline-none"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      >
        <option value="default">Default</option>
        <option value="qjs">QJS</option>
        <option value="v8">V8</option>
      </select>

      <select
        value={selectedTemplate}
        onChange={handleTemplateChange}
        className="text-[11px] px-1 py-0.5 rounded border outline-none"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      >
        <option value="">Templates...</option>
        {Object.entries(TEMPLATES).map(([key, t]) => (
          <option key={key} value={key}>
            {t.label}
          </option>
        ))}
      </select>

      <div className="relative" ref={dropdownRef}>
        <button
          onClick={() => setShowSavedScripts(!showSavedScripts)}
          className="text-[11px] px-1.5 py-0.5 rounded border"
          style={{
            borderColor: "var(--border)",
            color: "var(--text-secondary)",
          }}
        >
          Library
        </button>
        {showSavedScripts && (
          <div className="saved-scripts-dropdown">
            {savedScripts.length === 0 ? (
              <div
                className="px-3 py-2 text-xs"
                style={{ color: "var(--text-muted)" }}
              >
                No saved scripts
              </div>
            ) : (
              savedScripts.map((s) => (
                <div
                  key={s.id}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs cursor-pointer"
                  style={{ color: "var(--text-primary)" }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background =
                      "var(--hover-bg)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background =
                      "transparent")
                  }
                  onClick={() => handleLoadFromLibrary(s.id)}
                >
                  <span className="flex-1 truncate">{s.name}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteFromLibrary(s.id);
                    }}
                    className="text-red-400 text-[10px] px-1"
                  >
                    Del
                  </button>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      <button
        onClick={() =>
          saveToLibrary(editorRef.current?.getValue() ?? "")
        }
        className="text-[11px] px-1.5 py-0.5 rounded border"
        style={{
          borderColor: "var(--border)",
          color: "var(--text-secondary)",
        }}
      >
        Save
      </button>

      <button
        onClick={handleImport}
        className="text-[11px] px-1.5 py-0.5 rounded border"
        style={{
          borderColor: "var(--border)",
          color: "var(--text-secondary)",
        }}
        title="Import .js file"
      >
        Import
      </button>

      <button
        onClick={handleExport}
        className="text-[11px] px-1.5 py-0.5 rounded border"
        style={{
          borderColor: "var(--border)",
          color: "var(--text-secondary)",
        }}
        title="Export as .js"
      >
        Export
      </button>

      <button
        onClick={handleCopy}
        className="text-[11px] px-1.5 py-0.5 rounded border"
        style={{
          borderColor: "var(--border)",
          color: copySuccess ? "#22c55e" : "var(--text-secondary)",
        }}
      >
        {copySuccess ? "Copied!" : "Copy"}
      </button>
    </div>
  );
}
