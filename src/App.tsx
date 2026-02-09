import { useRef, useState, useEffect, useCallback } from "react";
import Navbar from "@/components/layout/Navbar.tsx";
import Sidebar from "@/components/layout/Sidebar.tsx";
import ScriptEditor from "@/components/editor/ScriptEditor.tsx";
import type { MonacoEditor } from "@/components/editor/ScriptEditor.tsx";
import TabBar from "@/components/editor/TabBar.tsx";
import EditorToolbar from "@/components/editor/EditorToolbar.tsx";
import EditorStatusBar from "@/components/editor/EditorStatusBar.tsx";
import ConsolePanel from "@/components/console/ConsolePanel.tsx";
import { useResizable, useResizablePercent } from "@/hooks/useResizable.ts";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";

export default function App() {
  const editorRef = useRef<MonacoEditor | null>(null);
  const [cursorLine, setCursorLine] = useState(1);
  const [cursorCol, setCursorCol] = useState(1);

  const sidebar = useResizable("frida-web-sidebar-width", 380, 200, 800, "x");
  const editorPane = useResizablePercent(
    "frida-web-editor-height",
    45,
    15,
    85,
    ".main-content",
  );

  const runScript = useSessionStore((s) => s.runScript);

  const handleRun = useCallback(() => {
    const source = editorRef.current?.getValue() ?? "";
    runScript(source);
  }, [runScript]);

  useKeyboardShortcuts(handleRun);

  useEffect(() => {
    useScriptsStore.getState().loadState();
  }, []);

  const handleCursorChange = useCallback((line: number, col: number) => {
    setCursorLine(line);
    setCursorCol(col);
  }, []);

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    e.stopPropagation();
    const file = e.dataTransfer?.files?.[0];
    if (file && file.name.endsWith(".js")) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        const text = ev.target?.result as string;
        editorRef.current?.setValue(text);
        useScriptsStore.getState().syncCurrentTab(text);
      };
      reader.readAsText(file);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <Navbar />
      <div className="flex flex-1 overflow-hidden">
        <div
          style={{
            width: sidebar.value,
            minWidth: sidebar.value,
          }}
          className="overflow-hidden"
        >
          <Sidebar />
        </div>
        <div
          className="resize-handle-x"
          onMouseDown={sidebar.onMouseDown}
        />
        <div className="flex-1 flex flex-col overflow-hidden main-content">
          <div
            className="flex flex-col overflow-hidden"
            style={{ height: `${editorPane.value}%` }}
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
          >
            <TabBar editorRef={editorRef} />
            <EditorToolbar editorRef={editorRef} />
            <div className="flex-1 overflow-hidden">
              <ScriptEditor
                editorRef={editorRef}
                onCursorChange={handleCursorChange}
              />
            </div>
            <EditorStatusBar line={cursorLine} col={cursorCol} />
          </div>
          <div
            className="resize-handle-y"
            onMouseDown={editorPane.onMouseDown}
          />
          <div
            className="flex flex-col overflow-hidden"
            style={{ height: `${100 - editorPane.value}%` }}
          >
            <ConsolePanel />
          </div>
        </div>
      </div>
    </div>
  );
}
