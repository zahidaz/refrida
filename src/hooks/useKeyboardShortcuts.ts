import { useEffect } from "react";
import { useConsoleStore } from "@/stores/console.ts";

export function useKeyboardShortcuts(onRun: () => void) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "K") {
        e.preventDefault();
        useConsoleStore.getState().clear();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onRun]);
}
