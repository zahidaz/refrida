import { useRef, useCallback } from "react";
import Editor, { type OnMount, type OnChange } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import { useThemeStore } from "@/stores/theme.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";

export type MonacoEditor = editor.IStandaloneCodeEditor;

interface Props {
  editorRef: React.MutableRefObject<MonacoEditor | null>;
  onCursorChange: (line: number, col: number) => void;
}

export default function ScriptEditor({ editorRef, onCursorChange }: Props) {
  const dark = useThemeStore((s) => s.dark);
  const updateTabContent = useScriptsStore((s) => s.updateTabContent);
  const runScript = useSessionStore((s) => s.runScript);
  const mounted = useRef(false);

  const handleMount: OnMount = useCallback(
    (editor) => {
      editorRef.current = editor;
      mounted.current = true;

      editor.onDidChangeCursorPosition((e) => {
        onCursorChange(e.position.lineNumber, e.position.column);
      });

      editor.addAction({
        id: "run-script",
        label: "Run Script",
        keybindings: [
          // eslint-disable-next-line no-bitwise
          (window.monaco?.KeyMod.CtrlCmd ?? 2048) |
            (window.monaco?.KeyCode.Enter ?? 3),
        ],
        run: () => {
          const source = editor.getValue();
          runScript(source);
        },
      });

      const tab = useScriptsStore.getState().getActiveTab();
      if (tab?.content) {
        editor.setValue(tab.content);
      }
    },
    [editorRef, onCursorChange, runScript],
  );

  const handleChange: OnChange = useCallback(
    (value) => {
      if (mounted.current && value !== undefined) {
        updateTabContent(value);
      }
    },
    [updateTabContent],
  );

  return (
    <Editor
      defaultLanguage="javascript"
      theme={dark ? "vs-dark" : "vs"}
      onMount={handleMount}
      onChange={handleChange}
      options={{
        fontSize: 13,
        fontFamily:
          "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        minimap: { enabled: false },
        lineNumbers: "on",
        tabSize: 2,
        insertSpaces: true,
        wordWrap: "off",
        scrollBeyondLastLine: false,
        automaticLayout: true,
        padding: { top: 8 },
      }}
    />
  );
}

declare global {
  interface Window {
    monaco?: {
      KeyMod: { CtrlCmd: number };
      KeyCode: { Enter: number };
    };
  }
}
