import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { processInfoScript, enumerateThreadsScript, enumerateEnvVarsScript } from "@/lib/utilityScripts.ts";
import { useConnectionStore } from "./connection.ts";
import { useSessionStore } from "./session.ts";
import { useConsoleStore } from "./console.ts";

export interface ProcessDetails {
  pid: number;
  arch: string;
  platform: string;
  pageSize: number;
  pointerSize: number;
  mainModule: { name: string; base: string; size: number; path: string };
  threadCount: number;
  moduleCount: number;
  rangeCount: number;
  totalMappedSize: number;
  currentThreadId: number;
}

export interface ThreadInfo {
  id: number;
  state: string;
  pc: string | null;
  sp: string | null;
}

export interface EnvVar {
  key: string;
  value: string;
}

type Section = "overview" | "threads" | "env" | "operations";

interface ProcessInfoState {
  info: ProcessDetails | null;
  threads: ThreadInfo[];
  envVars: EnvVar[];
  loading: boolean;
  loadingThreads: boolean;
  loadingEnv: boolean;
  error: string | null;
  activeSection: Section;
  envFilter: string;
  fetchInfo: () => Promise<void>;
  fetchThreads: () => Promise<void>;
  fetchEnvVars: () => Promise<void>;
  killProcess: () => Promise<void>;
  spawnProcess: (program: string) => Promise<void>;
  setActiveSection: (s: Section) => void;
  setEnvFilter: (f: string) => void;
  reset: () => void;
}

export const useProcessInfoStore = create<ProcessInfoState>((set, get) => ({
  info: null,
  threads: [],
  envVars: [],
  loading: false,
  loadingThreads: false,
  loadingEnv: false,
  error: null,
  activeSection: "overview",
  envFilter: "",

  setActiveSection: (activeSection) => set({ activeSection }),
  setEnvFilter: (envFilter) => set({ envFilter }),

  fetchInfo: async () => {
    set({ loading: true, error: null });
    const result = await runUtilityScript<ProcessDetails>(processInfoScript(), "process-info");
    if (result.error) {
      set({ loading: false, error: result.error });
    } else if (result.data[0]) {
      set({ loading: false, info: result.data[0] });
    } else {
      set({ loading: false, error: "No data returned" });
    }
  },

  fetchThreads: async () => {
    set({ loadingThreads: true });
    const result = await runUtilityScript<ThreadInfo>(enumerateThreadsScript(), "enumerate-threads");
    set({ loadingThreads: false, threads: result.data });
  },

  fetchEnvVars: async () => {
    set({ loadingEnv: true });
    const result = await runUtilityScript<EnvVar>(enumerateEnvVarsScript(), "enumerate-env");
    set({ loadingEnv: false, envVars: result.data });
  },

  killProcess: async () => {
    const pid = get().info?.pid ?? useSessionStore.getState().attachedPid;
    if (!pid) return;
    const client = useConnectionStore.getState().getClient();
    if (!client) return;
    try {
      await client.kill(pid);
      useConsoleStore.getState().append(`Killed process ${pid}`, "system");
    } catch (err) {
      useConsoleStore.getState().append(`Kill failed: ${(err as Error).message}`, "error");
    }
  },

  spawnProcess: async (program) => {
    const client = useConnectionStore.getState().getClient();
    if (!client) return;
    const append = useConsoleStore.getState().append;
    try {
      const pid = await client.spawn(program);
      append(`Spawned ${program} (PID ${pid})`, "system");
      await client.resume(pid);
      append(`Resumed PID ${pid}`, "system");
    } catch (err) {
      append(`Spawn failed: ${(err as Error).message}`, "error");
    }
  },

  reset: () => set({ info: null, threads: [], envVars: [], error: null }),
}));
