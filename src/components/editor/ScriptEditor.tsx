import { useRef, useCallback } from "react";
import Editor, { type OnMount, type OnChange } from "@monaco-editor/react";
import type { editor, languages } from "monaco-editor";
import { useThemeStore } from "@/stores/theme.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useSessionStore } from "@/stores/session.ts";
import { getFridaCompletions } from "@/lib/fridaCompletions.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";

export type MonacoEditor = editor.IStandaloneCodeEditor;

let completionsRegistered = false;

interface Props {
  editorRef: React.MutableRefObject<MonacoEditor | null>;
  onCursorChange: (line: number, col: number) => void;
}

export default function ScriptEditor({ editorRef, onCursorChange }: Props) {
  const dark = useThemeStore((s) => s.dark);
  const updateTabContent = useScriptsStore((s) => s.updateTabContent);
  const runScript = useSessionStore((s) => s.runScript);
  const isMobile = useIsMobile();
  const mounted = useRef(false);

  const handleMount: OnMount = useCallback(
    (editor, monaco) => {
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
          monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter,
        ],
        run: () => {
          const source = editor.getValue();
          runScript(source);
        },
      });

      if (!completionsRegistered) {
        completionsRegistered = true;
        const completions = getFridaCompletions();
        monaco.languages.registerCompletionItemProvider("javascript", {
          provideCompletionItems: (_model: unknown, position: { lineNumber: number; column: number }) => {
            const range = {
              startLineNumber: position.lineNumber,
              endLineNumber: position.lineNumber,
              startColumn: position.column,
              endColumn: position.column,
            };
            return {
              suggestions: completions.map((c) => ({
                ...c,
                range,
              })) as languages.CompletionItem[],
            };
          },
        });
      }

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
        fontSize: isMobile ? 12 : 13,
        fontFamily:
          "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        minimap: { enabled: false },
        lineNumbers: isMobile ? "off" : "on",
        tabSize: 2,
        insertSpaces: true,
        wordWrap: isMobile ? "on" : "off",
        scrollBeyondLastLine: false,
        automaticLayout: true,
        padding: { top: 8 },
        folding: !isMobile,
        glyphMargin: false,
        lineDecorationsWidth: isMobile ? 4 : undefined,
      }}
    />
  );
}
