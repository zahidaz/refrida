import { useConnectionStore } from "@/stores/connection.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import { useConsoleStore } from "@/stores/console.ts";

interface Props {
  cursorLine: number;
  cursorCol: number;
}

const RUNTIMES = ["default", "qjs", "v8"] as const;

export default function StatusBar({ cursorLine, cursorCol }: Props) {
  const connected = useConnectionStore((s) => s.connected);
  const serverUrl = useConnectionStore((s) => s.serverUrl);
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const scriptActive = useSessionStore((s) => s.scriptActive);
  const scriptRuntime = useSessionStore((s) => s.scriptRuntime);
  const setScriptRuntime = useSessionStore((s) => s.setScriptRuntime);
  const attachedPid = useSessionStore((s) => s.attachedPid);
  const attachedName = useSessionStore((s) => s.attachedName);
  const bottomPanelVisible = useLayoutStore((s) => s.bottomPanelVisible);
  const toggleBottomPanel = useLayoutStore((s) => s.toggleBottomPanel);
  const lineCount = useConsoleStore((s) => s.lines.length);

  function cycleRuntime() {
    const idx = RUNTIMES.indexOf(scriptRuntime as (typeof RUNTIMES)[number]);
    const next = RUNTIMES[(idx + 1) % RUNTIMES.length];
    setScriptRuntime(next);
  }

  return (
    <div
      className="flex items-center px-2 py-0.5 text-[11px] border-t"
      style={{
        borderColor: "var(--border)",
        background: "var(--bg-secondary)",
        color: "var(--text-muted)",
      }}
    >
      <span className="flex items-center gap-1.5">
        <span
          className="inline-block w-2 h-2 rounded-full"
          style={{ background: connected ? "#22c55e" : "#6b7280" }}
        />
        {connected ? serverUrl : "Disconnected"}
      </span>

      {sessionActive && (
        <>
          <span className="mx-2">|</span>
          <span>{attachedName} (PID {attachedPid})</span>
        </>
      )}

      {scriptActive && (
        <>
          <span className="mx-2">|</span>
          <span className="text-green-400">Script Active</span>
        </>
      )}

      <div className="flex-1" />

      <button
        onClick={toggleBottomPanel}
        className="flex items-center gap-1 mr-3 cursor-pointer"
        style={{ color: "var(--text-muted)" }}
        title={bottomPanelVisible ? "Hide Console (Ctrl+`)" : "Show Console (Ctrl+`)"}
      >
        <i className={`fa-solid ${bottomPanelVisible ? "fa-terminal" : "fa-terminal"}`} style={{ fontSize: 10 }} />
        Console
        {lineCount > 0 && (
          <span className="text-[10px]" style={{ color: "var(--accent-text)" }}>
            {lineCount}
          </span>
        )}
      </button>

      <span className="mr-3">
        Ln {cursorLine}, Col {cursorCol}
      </span>
      <button
        onClick={cycleRuntime}
        className="cursor-pointer hover:underline"
        style={{ color: "var(--text-muted)" }}
        title="Click to change runtime"
      >
        Runtime: {scriptRuntime}
      </button>
    </div>
  );
}
