import { useEffect } from "react";
import { useConsoleStore } from "@/stores/console.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import { useScriptsStore } from "@/stores/scripts.ts";

interface ShortcutHandlers {
  onRun: () => void;
  onImport: () => void;
  onSave: () => void;
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;

      if (mod && e.shiftKey && e.key === "K") {
        e.preventDefault();
        useConsoleStore.getState().clear();
        return;
      }

      if (mod && (e.key === "p" || e.key === "P") && !e.shiftKey) {
        e.preventDefault();
        const store = useLayoutStore.getState();
        store.setCommandPaletteOpen(!store.commandPaletteOpen);
        return;
      }

      if (mod && (e.key === "b" || e.key === "B") && !e.shiftKey) {
        e.preventDefault();
        useLayoutStore.getState().toggleSidePanel();
        return;
      }

      if (mod && e.key === "`") {
        e.preventDefault();
        useLayoutStore.getState().toggleBottomPanel();
        return;
      }

      if (mod && e.shiftKey && (e.key === "c" || e.key === "C")) {
        e.preventDefault();
        const store = useLayoutStore.getState();
        store.setConnectionDialogOpen(!store.connectionDialogOpen);
        return;
      }

      if (mod && (e.key === "s" || e.key === "S") && !e.shiftKey) {
        e.preventDefault();
        handlers.onSave();
        return;
      }

      if (mod && (e.key === "o" || e.key === "O") && !e.shiftKey) {
        e.preventDefault();
        handlers.onImport();
        return;
      }

      if (mod && (e.key === "t" || e.key === "T") && !e.shiftKey) {
        e.preventDefault();
        useScriptsStore.getState().addTab(() => "");
        return;
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [handlers]);
}
