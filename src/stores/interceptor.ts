import { create } from "zustand";
import { startMonitor, type MonitorHandle } from "@/lib/monitorRunner.ts";
import { useConsoleStore } from "./console.ts";
import { useLayoutStore } from "./layout.ts";

export interface HookTarget {
  type: "export" | "address";
  moduleName: string;
  exportName: string;
  address: string;
}

interface InterceptorState {
  target: HookTarget;
  logArgs: boolean;
  argCount: number;
  logReturn: boolean;
  modifyReturn: boolean;
  returnValue: string;
  customOnEnter: string;
  customOnLeave: string;
  mode: "insert" | "live";
  liveActive: boolean;
  liveError: string | null;
  setTarget: (t: Partial<HookTarget>) => void;
  setConfig: (cfg: Partial<Pick<InterceptorState, "logArgs" | "argCount" | "logReturn" | "modifyReturn" | "returnValue" | "customOnEnter" | "customOnLeave" | "mode">>) => void;
  generateCode: () => string;
  startLive: () => Promise<void>;
  stopLive: () => Promise<void>;
  quickHook: (moduleName: string, exportName: string, address: string) => void;
  reset: () => void;
}

let liveHandle: MonitorHandle | null = null;

function escapeStr(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function buildTargetExpr(target: HookTarget): string {
  if (target.type === "address" && target.address) {
    return `ptr("${escapeStr(target.address)}")`;
  }
  if (target.moduleName && target.exportName) {
    return `Module.findExportByName("${escapeStr(target.moduleName)}", "${escapeStr(target.exportName)}")`;
  }
  if (target.exportName) {
    return `Module.findExportByName(null, "${escapeStr(target.exportName)}")`;
  }
  return `ptr("0x0")`;
}

function buildCode(state: InterceptorState): string {
  const targetExpr = buildTargetExpr(state.target);
  const lines: string[] = [];

  lines.push(`var target = ${targetExpr};`);
  lines.push(`Interceptor.attach(target, {`);

  const onEnterLines: string[] = [];
  if (state.logArgs && state.argCount > 0) {
    const argParts: string[] = [];
    for (let i = 0; i < state.argCount; i++) {
      argParts.push(`"arg${i}: " + args[${i}]`);
    }
    onEnterLines.push(`    send({ event: "enter", target: target.toString(), args: [${argParts.join(", ")}] });`);
  }
  if (state.customOnEnter.trim()) {
    onEnterLines.push(`    ${state.customOnEnter.trim()}`);
  }

  if (onEnterLines.length > 0) {
    lines.push(`  onEnter: function(args) {`);
    lines.push(`    try {`);
    onEnterLines.forEach((l) => lines.push(l));
    lines.push(`    } catch(e) { send({ event: "error", message: e.message }); }`);
    lines.push(`  },`);
  }

  const onLeaveLines: string[] = [];
  if (state.logReturn) {
    onLeaveLines.push(`    send({ event: "leave", target: target.toString(), retval: retval.toString() });`);
  }
  if (state.modifyReturn && state.returnValue) {
    onLeaveLines.push(`    retval.replace(ptr("${escapeStr(state.returnValue)}"));`);
  }
  if (state.customOnLeave.trim()) {
    onLeaveLines.push(`    ${state.customOnLeave.trim()}`);
  }

  if (onLeaveLines.length > 0) {
    lines.push(`  onLeave: function(retval) {`);
    lines.push(`    try {`);
    onLeaveLines.forEach((l) => lines.push(l));
    lines.push(`    } catch(e) { send({ event: "error", message: e.message }); }`);
    lines.push(`  }`);
  }

  lines.push(`});`);
  lines.push(`send({ event: "__started__" });`);

  return lines.join("\n");
}

const DEFAULT_TARGET: HookTarget = { type: "export", moduleName: "", exportName: "", address: "" };

export const useInterceptorStore = create<InterceptorState>((set, get) => ({
  target: { ...DEFAULT_TARGET },
  logArgs: true,
  argCount: 3,
  logReturn: true,
  modifyReturn: false,
  returnValue: "",
  customOnEnter: "",
  customOnLeave: "",
  mode: "insert",
  liveActive: false,
  liveError: null,

  setTarget: (t) => set((s) => ({ target: { ...s.target, ...t } })),

  setConfig: (cfg) => set(cfg),

  generateCode: () => buildCode(get()),

  startLive: async () => {
    if (get().liveActive) return;
    const code = buildCode(get());
    const append = useConsoleStore.getState().append;
    set({ liveActive: true, liveError: null });

    const handle = await startMonitor<Record<string, unknown>>(
      code,
      (data) => {
        if (data.event === "__started__") {
          append("Hook attached.", "system");
          return;
        }
        if (data.event === "error") {
          append(`Hook error: ${data.message}`, "error");
          return;
        }
        append(JSON.stringify(data, null, 2), "info");
      },
      (error) => {
        set({ liveError: error, liveActive: false });
        append(`Hook failed: ${error}`, "error");
      },
      "interceptor-hook",
    );

    if (handle) {
      liveHandle = handle;
    } else {
      set({ liveActive: false });
    }
  },

  stopLive: async () => {
    if (liveHandle) {
      await liveHandle.stop();
      liveHandle = null;
    }
    set({ liveActive: false });
    useConsoleStore.getState().append("Hook detached.", "system");
  },

  quickHook: (moduleName, exportName, address) => {
    set({
      target: { type: "export", moduleName, exportName, address },
      logArgs: true,
      argCount: 3,
      logReturn: true,
      mode: "live",
    });
    const layout = useLayoutStore.getState();
    layout.setActiveActivity("interceptor");
    layout.setSidePanelVisible(true);
  },

  reset: () => {
    if (liveHandle) {
      liveHandle.stop();
      liveHandle = null;
    }
    set({
      target: { ...DEFAULT_TARGET },
      liveActive: false,
      liveError: null,
    });
  },
}));
