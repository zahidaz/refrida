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
  setScriptRuntime: (r: string) => void;
  attachToProcess: (pid: number, name: string) => Promise<void>;
  runScript: (source: string, scriptName?: string) => Promise<void>;
  unloadScript: () => Promise<void>;
  detachSession: () => Promise<void>;
  reset: () => void;
}

let currentSession: FridaSession | null = null;
let currentScript: FridaScript | null = null;

export const useSessionStore = create<SessionState>((set, get) => ({
  sessionActive: false,
  scriptActive: false,
  sessionInfoText: "",
  attachedPid: null,
  attachedName: "",
  scriptRuntime: "default",
  lastCrash: null,

  setScriptRuntime: (scriptRuntime) => set({ scriptRuntime }),

  attachToProcess: async (pid, name) => {
    const client = useConnectionStore.getState().getClient();
    if (!client) return;
    const append = useConsoleStore.getState().append;

    if (currentScript) {
      try {
        await currentScript.unload();
      } catch {}
      currentScript = null;
      set({ scriptActive: false });
    }
    if (currentSession && !currentSession.isDetached) {
      currentSession.detach();
    }

    append(`Attaching to ${name} (PID ${pid})...`, "system");
    try {
      currentSession = await client.attach(pid);
      currentSession.detached.connect((reason, crash) => {
        const reasonText = DETACH_REASONS[reason] || String(reason);
        if (crash) {
          set({ lastCrash: crash });
          append(
            `Session detached: ${reasonText} — ${crash.summary}`,
            "warning",
          );
        } else {
          append(`Session detached: ${reasonText}`, "warning");
        }
        set({
          sessionActive: false,
          scriptActive: false,
          attachedPid: null,
          attachedName: "",
          sessionInfoText: "",
        });
        currentSession = null;
        currentScript = null;
      });
      set({
        sessionActive: true,
        attachedPid: pid,
        attachedName: name,
        sessionInfoText: `${name} (PID ${pid})`,
        lastCrash: null,
      });
      append(`Attached to ${name} (PID ${pid})`, "system");
    } catch (err) {
      append(`Attach failed: ${(err as Error).message}`, "error");
    }
  },

  runScript: async (source, scriptName) => {
    if (!currentSession || currentSession.isDetached) {
      useConsoleStore
        .getState()
        .append("No active session. Attach to a process first.", "error");
      return;
    }

    if (currentScript) {
      try {
        await currentScript.unload();
      } catch {}
      currentScript = null;
    }

    if (!source.trim()) {
      useConsoleStore.getState().append("Script is empty.", "warning");
      return;
    }

    const append = useConsoleStore.getState().append;
    const { scriptRuntime } = get();

    try {
      const opts: { runtime?: string } = {};
      if (scriptRuntime !== "default") {
        opts.runtime = scriptRuntime;
      }
      currentScript = await currentSession.createScript(source, opts);
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
      await currentScript.load();
      set({ scriptActive: true });
      useConsoleStore.getState().bumpRunId();
      const label = scriptName ? `Script loaded (${scriptName}).` : "Script loaded.";
      append(label, "system");
    } catch (err) {
      append(`Script error: ${(err as Error).message}`, "error");
      currentScript = null;
    }
  },

  unloadScript: async () => {
    if (!currentScript) return;
    const append = useConsoleStore.getState().append;
    try {
      await currentScript.unload();
      append("Script unloaded.", "system");
    } catch (err) {
      append(`Unload failed: ${(err as Error).message}`, "error");
    }
    currentScript = null;
    set({ scriptActive: false });
  },

  detachSession: async () => {
    const append = useConsoleStore.getState().append;
    if (currentScript) {
      try {
        await currentScript.unload();
      } catch {}
      currentScript = null;
      set({ scriptActive: false });
    }
    if (currentSession && !currentSession.isDetached) {
      currentSession.detach();
      append("Detached from session.", "system");
    }
    currentSession = null;
    set({
      sessionActive: false,
      attachedPid: null,
      attachedName: "",
      sessionInfoText: "",
    });
  },

  reset: () => {
    if (currentScript) {
      try {
        currentScript.unload();
      } catch {}
      currentScript = null;
    }
    if (currentSession && !currentSession.isDetached) {
      currentSession.detach();
    }
    currentSession = null;
    set({
      sessionActive: false,
      scriptActive: false,
      attachedPid: null,
      attachedName: "",
      sessionInfoText: "",
      lastCrash: null,
    });
  },
}));
