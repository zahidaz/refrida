import { create } from "zustand";
import { startMonitor, type MonitorHandle } from "@/lib/monitorRunner.ts";
import { stalkerTraceScript } from "@/lib/utilityScripts.ts";

export interface StalkerEvent {
  type: string;
  address: string;
  target?: string;
  module: string | null;
  symbol: string | null;
  ts: number;
  event?: string;
}

interface StalkerState {
  active: boolean;
  events: StalkerEvent[];
  error: string | null;
  threadId: string;
  eventTypes: Record<string, boolean>;
  filterModule: string;
  filterSearch: string;
  start: () => Promise<void>;
  stop: () => Promise<void>;
  clear: () => void;
  setThreadId: (id: string) => void;
  setEventTypes: (types: Record<string, boolean>) => void;
  setFilterModule: (m: string) => void;
  setFilterSearch: (s: string) => void;
  exportTrace: () => void;
  reset: () => void;
}

let stalkerHandle: MonitorHandle | null = null;

const DEFAULT_EVENT_TYPES: Record<string, boolean> = {
  call: true,
  ret: false,
  exec: false,
  block: false,
  compile: false,
};

export const useStalkerStore = create<StalkerState>((set, get) => ({
  active: false,
  events: [],
  error: null,
  threadId: "",
  eventTypes: { ...DEFAULT_EVENT_TYPES },
  filterModule: "",
  filterSearch: "",

  setThreadId: (threadId) => set({ threadId }),
  setEventTypes: (eventTypes) => set({ eventTypes }),
  setFilterModule: (filterModule) => set({ filterModule }),
  setFilterSearch: (filterSearch) => set({ filterSearch }),

  start: async () => {
    if (get().active) return;
    set({ active: true, error: null });
    const { threadId, eventTypes } = get();
    const handle = await startMonitor<StalkerEvent>(
      stalkerTraceScript(threadId, eventTypes),
      (data) => {
        if (data.event === "__started__") return;
        set((s) => ({ events: [...s.events.slice(-1999), data] }));
      },
      (error) => set({ error, active: false }),
      "stalker-trace",
    );
    if (handle) {
      stalkerHandle = handle;
    } else {
      set({ active: false });
    }
  },

  stop: async () => {
    if (stalkerHandle) {
      await stalkerHandle.stop();
      stalkerHandle = null;
    }
    set({ active: false });
  },

  clear: () => set({ events: [] }),

  exportTrace: () => {
    const { events } = get();
    if (events.length === 0) return;
    const json = JSON.stringify(events, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `stalker-trace-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  },

  reset: () => {
    if (stalkerHandle) {
      stalkerHandle.stop();
      stalkerHandle = null;
    }
    set({ active: false, events: [], error: null });
  },
}));

export function getFilteredEvents(state: StalkerState): StalkerEvent[] {
  let result = state.events;
  if (state.filterModule) {
    const mod = state.filterModule.toLowerCase();
    result = result.filter((e) => e.module?.toLowerCase().includes(mod));
  }
  if (state.filterSearch) {
    const q = state.filterSearch.toLowerCase();
    result = result.filter(
      (e) =>
        e.address.toLowerCase().includes(q) ||
        e.symbol?.toLowerCase().includes(q) ||
        e.module?.toLowerCase().includes(q),
    );
  }
  return result;
}
