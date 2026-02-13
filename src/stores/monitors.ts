import { create } from "zustand";
import { startMonitor, type MonitorHandle } from "@/lib/monitorRunner.ts";
import { networkMonitorScript, fileMonitorScript } from "@/lib/utilityScripts.ts";

export interface NetworkEvent {
  event: string;
  fd: number;
  ip?: string;
  port?: number;
  length?: number;
  preview?: number[];
  result?: number;
  ts: number;
}

export interface FileEvent {
  event: string;
  fd: number;
  path?: string;
  flags?: number;
  length?: number;
  ts: number;
}

interface MonitorsState {
  networkActive: boolean;
  networkEvents: NetworkEvent[];
  networkError: string | null;
  fileActive: boolean;
  fileEvents: FileEvent[];
  fileError: string | null;
  activeTab: "network" | "files";
  setActiveTab: (tab: "network" | "files") => void;
  startNetwork: () => Promise<void>;
  stopNetwork: () => Promise<void>;
  clearNetwork: () => void;
  startFile: () => Promise<void>;
  stopFile: () => Promise<void>;
  clearFile: () => void;
  stopAll: () => Promise<void>;
}

let networkHandle: MonitorHandle | null = null;
let fileHandle: MonitorHandle | null = null;

export const useMonitorsStore = create<MonitorsState>((set, get) => ({
  networkActive: false,
  networkEvents: [],
  networkError: null,
  fileActive: false,
  fileEvents: [],
  fileError: null,
  activeTab: "network",

  setActiveTab: (activeTab) => set({ activeTab }),

  startNetwork: async () => {
    if (get().networkActive) return;
    set({ networkActive: true, networkError: null });
    const handle = await startMonitor<NetworkEvent>(
      networkMonitorScript(),
      (data) => {
        if (data.event === "__started__") return;
        set((s) => ({ networkEvents: [...s.networkEvents.slice(-999), data] }));
      },
      (error) => set({ networkError: error, networkActive: false }),
    );
    if (handle) {
      networkHandle = handle;
    } else {
      set({ networkActive: false });
    }
  },

  stopNetwork: async () => {
    if (networkHandle) {
      await networkHandle.stop();
      networkHandle = null;
    }
    set({ networkActive: false });
  },

  clearNetwork: () => set({ networkEvents: [] }),

  startFile: async () => {
    if (get().fileActive) return;
    set({ fileActive: true, fileError: null });
    const handle = await startMonitor<FileEvent>(
      fileMonitorScript(),
      (data) => {
        if (data.event === "__started__") return;
        set((s) => ({ fileEvents: [...s.fileEvents.slice(-999), data] }));
      },
      (error) => set({ fileError: error, fileActive: false }),
    );
    if (handle) {
      fileHandle = handle;
    } else {
      set({ fileActive: false });
    }
  },

  stopFile: async () => {
    if (fileHandle) {
      await fileHandle.stop();
      fileHandle = null;
    }
    set({ fileActive: false });
  },

  clearFile: () => set({ fileEvents: [] }),

  stopAll: async () => {
    await get().stopNetwork();
    await get().stopFile();
  },
}));
