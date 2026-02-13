import { useRef, useState, useEffect, useCallback, useMemo } from "react";
import TitleBar from "@/components/layout/TitleBar.tsx";
import ActivityBar from "@/components/layout/ActivityBar.tsx";
import SidePanel from "@/components/layout/SidePanel.tsx";
import StatusBar from "@/components/layout/StatusBar.tsx";
import CommandPalette from "@/components/layout/CommandPalette.tsx";
import ConnectionDialog from "@/components/connection/ConnectionDialog.tsx";
import ProcessPicker from "@/components/connection/ProcessPicker.tsx";
import AboutDialog from "@/components/layout/AboutDialog.tsx";
import WelcomeScreen from "@/components/layout/WelcomeScreen.tsx";
import SaveDialog from "@/components/ui/SaveDialog.tsx";
import ScriptEditor from "@/components/editor/ScriptEditor.tsx";
import type { MonacoEditor } from "@/components/editor/ScriptEditor.tsx";
import TabBar from "@/components/editor/TabBar.tsx";
import ConsolePanel from "@/components/console/ConsolePanel.tsx";
import { useResizable, useResizablePercent } from "@/hooks/useResizable.ts";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts.ts";
import { importFile } from "@/lib/fileIO.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useLayoutStore } from "@/stores/layout.ts";

export default function App() {
  const editorRef = useRef<MonacoEditor | null>(null);
  const [cursorLine, setCursorLine] = useState(1);
  const [cursorCol, setCursorCol] = useState(1);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);

  const sidePanelVisible = useLayoutStore((s) => s.sidePanelVisible);
  const sidePanelWidth = useLayoutStore((s) => s.sidePanelWidth);
  const setSidePanelWidth = useLayoutStore((s) => s.setSidePanelWidth);
  const bottomPanelVisible = useLayoutStore((s) => s.bottomPanelVisible);
  const setBottomPanelVisible = useLayoutStore((s) => s.setBottomPanelVisible);
  const commandPaletteOpen = useLayoutStore((s) => s.commandPaletteOpen);
  const connectionDialogOpen = useLayoutStore((s) => s.connectionDialogOpen);
  const processPickerOpen = useLayoutStore((s) => s.processPickerOpen);
  const aboutOpen = useLayoutStore((s) => s.aboutOpen);
  const welcomeOpen = useLayoutStore((s) => s.welcomeOpen);
  const setWelcomeOpen = useLayoutStore((s) => s.setWelcomeOpen);

  const sideResize = useResizable(
    "refrida-side-panel-width",
    300,
    150,
    600,
    "x",
  );
  const editorPane = useResizablePercent(
    "refrida-editor-height",
    55,
    15,
    85,
    ".main-content",
  );

  useEffect(() => {
    setSidePanelWidth(sideResize.value);
  }, [sideResize.value, setSidePanelWidth]);

  const runScript = useSessionStore((s) => s.runScript);

  const handleRun = useCallback(() => {
    if (welcomeOpen) setWelcomeOpen(false);
    const source = editorRef.current?.getValue() ?? "";
    const tab = useScriptsStore.getState().getActiveTab();
    runScript(source, tab?.name);
    if (!bottomPanelVisible) setBottomPanelVisible(true);
  }, [runScript, bottomPanelVisible, setBottomPanelVisible, welcomeOpen, setWelcomeOpen]);

  const handleEditorLoad = useCallback((text: string) => {
    editorRef.current?.setValue(text);
    useScriptsStore.getState().syncCurrentTab(text);
  }, []);

  const handleImport = useCallback(() => {
    importFile(handleEditorLoad);
  }, [handleEditorLoad]);

  const handleSave = useCallback(() => {
    setSaveDialogOpen(true);
  }, []);

  const shortcutHandlers = useMemo(
    () => ({
      onRun: handleRun,
      onImport: handleImport,
      onSave: handleSave,
    }),
    [handleRun, handleImport, handleSave],
  );

  useKeyboardShortcuts(shortcutHandlers);

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
        handleEditorLoad(ev.target?.result as string);
      };
      reader.readAsText(file);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <TitleBar editorRef={editorRef} onSave={handleSave} />

      <div className="flex flex-1 overflow-hidden">
        <ActivityBar />

        {sidePanelVisible && (
          <>
            <div
              style={{
                width: sidePanelWidth,
                minWidth: sidePanelWidth,
              }}
              className="overflow-hidden"
            >
              <SidePanel onLoadScript={handleEditorLoad} />
            </div>
            <div
              className="resize-handle-x"
              onMouseDown={sideResize.onMouseDown}
            />
          </>
        )}

        <div className="flex-1 flex flex-col overflow-hidden main-content">
          <div
            className="flex flex-col overflow-hidden"
            style={{
              height: bottomPanelVisible ? `${editorPane.value}%` : "100%",
            }}
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
          >
            <TabBar editorRef={editorRef} onRun={handleRun} />
            <div className="flex-1 overflow-hidden">
              {welcomeOpen ? (
                <WelcomeScreen
                  onLoadScript={(code) => {
                    handleEditorLoad(code);
                    setWelcomeOpen(false);
                  }}
                />
              ) : (
                <ScriptEditor
                  editorRef={editorRef}
                  onCursorChange={handleCursorChange}
                />
              )}
            </div>
          </div>

          {bottomPanelVisible && (
            <>
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
            </>
          )}
        </div>
      </div>

      <StatusBar cursorLine={cursorLine} cursorCol={cursorCol} />

      {commandPaletteOpen && <CommandPalette onRun={handleRun} />}
      {connectionDialogOpen && <ConnectionDialog />}
      {processPickerOpen && <ProcessPicker />}
      {aboutOpen && <AboutDialog />}
      {saveDialogOpen && (
        <SaveDialog
          defaultName={useScriptsStore.getState().getActiveTab()?.name ?? ""}
          onSave={(name) => {
            useScriptsStore.getState().saveToLibrary(
              editorRef.current?.getValue() ?? "",
              name,
            );
            setSaveDialogOpen(false);
          }}
          onClose={() => setSaveDialogOpen(false)}
        />
      )}
    </div>
  );
}
