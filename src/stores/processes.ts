import { create } from "zustand";
import type { FridaProcess, FridaApplication } from "@/lib/frida.ts";
import { useConnectionStore } from "./connection.ts";
import { useConsoleStore } from "./console.ts";

type SortField = "pid" | "name";
type ListTab = "processes" | "applications";

interface ProcessesState {
  processes: FridaProcess[];
  applications: FridaApplication[];
  filterText: string;
  sortField: SortField;
  sortAsc: boolean;
  activeTab: ListTab;
  autoRefresh: boolean;
  setProcesses: (p: FridaProcess[]) => void;
  setApplications: (a: FridaApplication[]) => void;
  setFilterText: (t: string) => void;
  setActiveTab: (t: ListTab) => void;
  toggleSort: (field: SortField) => void;
  refreshProcesses: () => Promise<void>;
  refreshApplications: () => Promise<void>;
  killProcess: (pid: number) => Promise<void>;
  toggleAutoRefresh: () => void;
  stopAutoRefresh: () => void;
  reset: () => void;
}

let autoRefreshTimer: ReturnType<typeof setInterval> | null = null;

export const useProcessesStore = create<ProcessesState>((set, get) => ({
  processes: [],
  applications: [],
  filterText: "",
  sortField: "pid",
  sortAsc: true,
  activeTab: "processes",
  autoRefresh: false,

  setProcesses: (processes) => set({ processes }),
  setApplications: (applications) => set({ applications }),
  setFilterText: (filterText) => set({ filterText }),
  setActiveTab: (activeTab) => set({ activeTab }),

  toggleSort: (field) =>
    set((state) => {
      if (state.sortField === field) return { sortAsc: !state.sortAsc };
      return { sortField: field, sortAsc: true };
    }),

  refreshProcesses: async () => {
    const client = useConnectionStore.getState().getClient();
    if (!client) return;
    try {
      const processes = await client.enumerateProcesses();
      set({ processes });
    } catch (err) {
      useConsoleStore
        .getState()
        .append(`Refresh failed: ${(err as Error).message}`, "error");
    }
  },

  refreshApplications: async () => {
    const client = useConnectionStore.getState().getClient();
    if (!client) return;
    try {
      const apps = await client.enumerateApplications();
      set({ applications: apps });
    } catch (err) {
      useConsoleStore
        .getState()
        .append(
          `Failed to list applications: ${(err as Error).message}`,
          "error",
        );
    }
  },

  killProcess: async (pid) => {
    const client = useConnectionStore.getState().getClient();
    if (!client) return;
    try {
      await client.kill(pid);
      useConsoleStore.getState().append(`Killed PID ${pid}`, "system");
      set((state) => ({
        processes: state.processes.filter((p) => p.pid !== pid),
      }));
    } catch (err) {
      useConsoleStore
        .getState()
        .append(`Kill failed: ${(err as Error).message}`, "error");
    }
  },

  toggleAutoRefresh: () => {
    const { autoRefresh } = get();
    if (autoRefresh) {
      get().stopAutoRefresh();
    } else {
      set({ autoRefresh: true });
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      autoRefreshTimer = setInterval(async () => {
        const client = useConnectionStore.getState().getClient();
        const connected = useConnectionStore.getState().connected;
        if (!client || !connected) {
          get().stopAutoRefresh();
          return;
        }
        try {
          const [processes, apps] = await Promise.all([
            client.enumerateProcesses(),
            client.enumerateApplications(),
          ]);
          set({ processes, applications: apps });
        } catch {}
      }, 3000);
    }
  },

  stopAutoRefresh: () => {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
    }
    set({ autoRefresh: false });
  },

  reset: () => {
    const { stopAutoRefresh } = get();
    stopAutoRefresh();
    set({ processes: [], applications: [] });
  },
}));

export function getFilteredProcesses(state: ProcessesState): FridaProcess[] {
  const q = state.filterText.trim().toLowerCase();
  let result = state.processes;
  if (q) {
    result = result.filter(
      (p) =>
        p.name.toLowerCase().includes(q) || String(p.pid).includes(q),
    );
  }
  return [...result].sort((a, b) => {
    const cmp =
      state.sortField === "pid"
        ? a.pid - b.pid
        : a.name.localeCompare(b.name);
    return state.sortAsc ? cmp : -cmp;
  });
}

export function getFilteredApplications(
  state: ProcessesState,
): FridaApplication[] {
  const q = state.filterText.trim().toLowerCase();
  let result = state.applications;
  if (q) {
    result = result.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.identifier.toLowerCase().includes(q) ||
        String(a.pid).includes(q),
    );
  }
  return [...result].sort((a, b) => {
    const cmp =
      state.sortField === "pid"
        ? a.pid - b.pid
        : a.name.localeCompare(b.name);
    return state.sortAsc ? cmp : -cmp;
  });
}
