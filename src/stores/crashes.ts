import { create } from "zustand";
import { getItem, setItem } from "@/lib/storage.ts";
import type { FridaCrash } from "@/lib/frida.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

const STORAGE_KEY = "refrida-crashes";

export interface CrashInfo {
  id: string;
  timestamp: string;
  processName: string;
  pid: number;
  summary: string;
  reason: string;
}

interface CrashesState {
  crashes: CrashInfo[];
  expanded: string | null;
  hasNew: boolean;
  addCrash: (processName: string, pid: number, reason: string, crash: FridaCrash) => void;
  toggleExpand: (id: string) => void;
  clearBadge: () => void;
  clearAll: () => void;
  copyCrash: (c: CrashInfo) => void;
  loadState: () => void;
  reset: () => void;
}

function persist(crashes: CrashInfo[]) {
  setItem(STORAGE_KEY, crashes);
}

export const useCrashesStore = create<CrashesState>((set, get) => ({
  crashes: [],
  expanded: null,
  hasNew: false,

  loadState: () => {
    const saved = getItem<CrashInfo[]>(STORAGE_KEY, []);
    if (saved.length > 0) set({ crashes: saved });
  },

  addCrash: (processName, pid, reason, crash) => {
    const entry: CrashInfo = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      timestamp: new Date().toISOString(),
      processName,
      pid,
      summary: crash.summary,
      reason,
    };
    const crashes = [entry, ...get().crashes].slice(0, 100);
    persist(crashes);
    set({ crashes, hasNew: true });
  },

  toggleExpand: (id) => {
    set({ expanded: get().expanded === id ? null : id });
  },

  clearBadge: () => set({ hasNew: false }),

  clearAll: () => {
    persist([]);
    set({ crashes: [], expanded: null, hasNew: false });
  },

  copyCrash: (c) => {
    const text = `Crash: ${c.processName} (PID ${c.pid})\nReason: ${c.reason}\nSummary: ${c.summary}\nTime: ${c.timestamp}`;
    copyToClipboard(text);
  },

  reset: () => set({ expanded: null, hasNew: false }),
}));
