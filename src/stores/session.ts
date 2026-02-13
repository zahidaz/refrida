import { create } from "zustand";
import {
  DETACH_REASONS,
  type FridaCrash,
  type FridaSession,
  type FridaScript,
} from "@/lib/frida.ts";
import { useConnectionStore } from "./connection.ts";
import { useConsoleStore } from "./console.ts";

interface SessionState {
  sessionActive: boolean;
  scriptActive: boolean;
  sessionInfoText: string;
  attachedPid: number | null;
  attachedName: string;
  scriptRuntime: string;
  lastCrash: FridaCrash | null;
  busy: boolean;
  busyLabel: string;
  setScriptRuntime: (r: string) => void;
  attachToProcess: (pid: number, name: string) => Promise<void>;
  runScript: (source: string, scriptName?: string) => Promise<void>;
  unloadScript: () => Promise<void>;
  detachSession: () => Promise<void>;
  cancelBusy: () => void;
  reset: () => void;
}

let currentSession: FridaSession | null = null;
let currentScript: FridaScript | null = null;
let busyAbort: AbortController | null = null;

async function cleanupScript(silent?: boolean) {
  if (!currentScript) return;
  try {
    await currentScript.unload();
  } catch {}
  currentScript = null;
  if (!silent) {
    useConsoleStore.getState().append("Script unloaded.", "system");
  }
}

function cleanupSession() {
  if (currentSession && !currentSession.isDetached) {
    currentSession.detach();
  }
  currentSession = null;
  currentScript = null;
}

function abortable<T>(promise: Promise<T>): Promise<T> {
  busyAbort = new AbortController();
  const { signal } = busyAbort;
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("Cancelled", "AbortError")));
    }),
  ]);
}

const CLEAN_STATE = {
  sessionActive: false,
  scriptActive: false,
  attachedPid: null,
  attachedName: "",
  sessionInfoText: "",
  lastCrash: null,
  busy: false,
  busyLabel: "",
} as const;

export const useSessionStore = create<SessionState>((set, get) => ({
  sessionActive: false,
  scriptActive: false,
  sessionInfoText: "",
  attachedPid: null,
  attachedName: "",
  scriptRuntime: "default",
  lastCrash: null,
  busy: false,
  busyLabel: "",

  setScriptRuntime: (scriptRuntime) => set({ scriptRuntime }),

  attachToProcess: async (pid, name) => {
    const client = useConnectionStore.getState().getClient();
    if (!client || get().busy) return;
    const append = useConsoleStore.getState().append;

    set({ busy: true, busyLabel: "Attaching..." });

    await cleanupScript(true);
    set({ scriptActive: false });
    cleanupSession();

    append(`Attaching to ${name} (PID ${pid})...`, "system");
    try {
      currentSession = await abortable(client.attach(pid));
      currentSession.detached.connect((reason, crash) => {
        const reasonText = DETACH_REASONS[reason] || String(reason);
        if (crash) {
          append(`Session detached: ${reasonText} — ${crash.summary}`, "warning");
          set({ ...CLEAN_STATE, lastCrash: crash });
        } else {
          append(`Session detached: ${reasonText}`, "warning");
          set(CLEAN_STATE);
        }
        currentSession = null;
        currentScript = null;
      });
      set({
        sessionActive: true,
        attachedPid: pid,
        attachedName: name,
        sessionInfoText: `${name} (PID ${pid})`,
        lastCrash: null,
        busy: false,
        busyLabel: "",
      });
      append(`Attached to ${name} (PID ${pid})`, "system");
    } catch (err) {
      if ((err as DOMException).name === "AbortError") {
        append("Attach cancelled.", "warning");
        set(CLEAN_STATE);
      } else {
        append(`Attach failed: ${(err as Error).message}`, "error");
        set({ busy: false, busyLabel: "" });
      }
    } finally {
      busyAbort = null;
    }
  },

  runScript: async (source, scriptName) => {
    if (!currentSession || currentSession.isDetached) {
      useConsoleStore
        .getState()
        .append("No active session. Attach to a process first.", "error");
      return;
    }
    if (!useConnectionStore.getState().connected) {
      useConsoleStore.getState().append("Not connected.", "error");
      return;
    }
    if (get().busy) return;

    if (currentScript) {
      await cleanupScript(true);
      set({ scriptActive: false });
    }

    if (!source.trim()) {
      useConsoleStore.getState().append("Script is empty.", "warning");
      return;
    }

    const append = useConsoleStore.getState().append;
    const { scriptRuntime } = get();
    set({ busy: true, busyLabel: "Loading script..." });

    try {
      const opts: { runtime?: string } = {};
      if (scriptRuntime !== "default") {
        opts.runtime = scriptRuntime;
      }
      currentScript = await abortable(currentSession.createScript(source, opts));
      currentScript.message.connect((message) => {
        if (message.type === "send") {
          const payload =
            typeof message.payload === "string"
              ? message.payload
              : JSON.stringify(message.payload, null, 2);
          append(payload, "info");
        } else if (message.type === "error") {
          let text = message.description || "Unknown error";
          if (message.stack) text += "\n" + message.stack;
          append(text, "error");
        }
      });
      currentScript.logHandler = (level, text) => {
        const levelMap: Record<string, "error" | "warning"> = {
          error: "error",
          warning: "warning",
        };
        append(`[${level}] ${text}`, levelMap[level] || "info");
      };
      currentScript.destroyed.connect(() => {
        set({ scriptActive: false });
        currentScript = null;
      });
      await abortable(currentScript.load());
      set({ scriptActive: true, busy: false, busyLabel: "" });
      useConsoleStore.getState().bumpRunId();
      const label = scriptName ? `Script loaded (${scriptName}).` : "Script loaded.";
      append(label, "system");
    } catch (err) {
      if ((err as DOMException).name === "AbortError") {
        append("Script loading cancelled.", "warning");
        if (currentScript) {
          try { await currentScript.unload(); } catch {}
        }
        currentScript = null;
        set({ scriptActive: false, busy: false, busyLabel: "" });
      } else {
        append(`Script error: ${(err as Error).message}`, "error");
        currentScript = null;
        set({ busy: false, busyLabel: "" });
      }
    } finally {
      busyAbort = null;
    }
  },

  unloadScript: async () => {
    if (!currentScript) return;
    await cleanupScript();
    set({ scriptActive: false });
  },

  detachSession: async () => {
    const append = useConsoleStore.getState().append;
    await cleanupScript(true);
    if (currentSession && !currentSession.isDetached) {
      currentSession.detach();
      append("Detached from session.", "system");
    }
    currentSession = null;
    currentScript = null;
    set(CLEAN_STATE);
  },

  cancelBusy: () => {
    if (busyAbort) {
      busyAbort.abort();
      busyAbort = null;
    }
  },

  reset: () => {
    if (busyAbort) {
      busyAbort.abort();
      busyAbort = null;
    }
    cleanupSession();
    set(CLEAN_STATE);
  },
}));
