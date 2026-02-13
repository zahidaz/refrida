import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { evalScript } from "@/lib/utilityScripts.ts";
import { useConsoleStore } from "./console.ts";

interface ReplState {
  history: string[];
  historyIndex: number;
  input: string;
  running: boolean;
  setInput: (v: string) => void;
  execute: () => Promise<void>;
  historyUp: () => void;
  historyDown: () => void;
  reset: () => void;
}

export const useReplStore = create<ReplState>((set, get) => ({
  history: [],
  historyIndex: -1,
  input: "",
  running: false,

  setInput: (input) => set({ input }),

  execute: async () => {
    const { input, history } = get();
    const trimmed = input.trim();
    if (!trimmed) return;

    const console = useConsoleStore.getState();
    console.append(`> ${trimmed}`, "system");

    set({
      running: true,
      history: [trimmed, ...history].slice(0, 100),
      historyIndex: -1,
      input: "",
    });

    const result = await runUtilityScript(evalScript(trimmed));

    if (result.error) {
      console.append(result.error, "error");
    } else {
      for (const item of result.data) {
        const text =
          typeof item === "string"
            ? item
            : JSON.stringify(item, null, 2);
        console.append(text, "info");
      }
    }

    set({ running: false });
  },

  historyUp: () => {
    const { history, historyIndex } = get();
    if (historyIndex < history.length - 1) {
      const next = historyIndex + 1;
      set({ historyIndex: next, input: history[next] });
    }
  },

  historyDown: () => {
    const { history, historyIndex } = get();
    if (historyIndex > 0) {
      const next = historyIndex - 1;
      set({ historyIndex: next, input: history[next] });
    } else if (historyIndex === 0) {
      set({ historyIndex: -1, input: "" });
    }
  },

  reset: () =>
    set({
      history: [],
      historyIndex: -1,
      input: "",
      running: false,
    }),
}));
