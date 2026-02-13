import { useEffect } from "react";
import { useCrashesStore, type CrashInfo } from "@/stores/crashes.ts";

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function CrashRow({ crash }: { crash: CrashInfo }) {
  const { expanded, toggleExpand, copyCrash } = useCrashesStore();
  const isExpanded = expanded === crash.id;

  return (
    <div
      className="border-b"
      style={{ borderColor: "var(--border)" }}
    >
      <div
        className="flex items-center gap-2 px-3 py-2 cursor-pointer hover-row"
        onClick={() => toggleExpand(crash.id)}
      >
        <i
          className={`fa-solid fa-chevron-right text-[8px] transition-transform ${isExpanded ? "rotate-90" : ""}`}
          style={{ color: "var(--text-muted)" }}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <i className="fa-solid fa-skull-crossbones text-[9px]" style={{ color: "#ef4444" }} />
            <span className="text-[11px] font-medium truncate" style={{ color: "var(--text-primary)" }}>
              {crash.processName}
            </span>
            <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>
              PID {crash.pid}
            </span>
          </div>
          <div className="text-[9px] mt-0.5 truncate" style={{ color: "var(--text-muted)" }}>
            {crash.reason}
          </div>
        </div>
        <div className="text-[9px] text-right shrink-0" style={{ color: "var(--text-muted)" }}>
          <div>{formatTime(crash.timestamp)}</div>
          <div>{formatDate(crash.timestamp)}</div>
        </div>
      </div>
      {isExpanded && (
        <div
          className="px-3 pb-2 pt-0"
        >
          <div
            className="text-[10px] p-2 rounded font-mono whitespace-pre-wrap break-all"
            style={{
              background: "var(--bg-primary)",
              color: "var(--text-secondary)",
              border: "1px solid var(--border)",
            }}
          >
            {crash.summary}
          </div>
          <div className="flex gap-1.5 mt-1.5">
            <button
              onClick={(e) => { e.stopPropagation(); copyCrash(crash); }}
              className="text-[9px] px-2 py-0.5 rounded flex items-center gap-1"
              style={{
                color: "var(--text-secondary)",
                border: "1px solid var(--border)",
              }}
            >
              <i className="fa-solid fa-copy" style={{ fontSize: 8 }} />
              Copy
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function CrashesPanel() {
  const { crashes, clearAll, clearBadge, loadState } = useCrashesStore();

  useEffect(() => {
    loadState();
    clearBadge();
  }, [loadState, clearBadge]);

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-2 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <span className="text-xs font-semibold flex-1" style={{ color: "var(--text-primary)" }}>
          Crashes
          {crashes.length > 0 && (
            <span
              className="ml-1.5 text-[9px] font-normal px-1.5 py-px rounded-full"
              style={{ background: "var(--hover-bg)", color: "var(--text-muted)" }}
            >
              {crashes.length}
            </span>
          )}
        </span>
        {crashes.length > 0 && (
          <button
            onClick={clearAll}
            className="text-[9px] px-1.5 py-0.5 rounded"
            style={{ color: "var(--text-muted)" }}
            title="Clear all crashes"
          >
            <i className="fa-solid fa-trash" style={{ fontSize: 9 }} />
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto">
        {crashes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 px-4">
            <i className="fa-solid fa-shield-halved text-xl" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
            <span className="text-[11px] text-center" style={{ color: "var(--text-muted)" }}>
              No crashes recorded
            </span>
            <span className="text-[9px] text-center" style={{ color: "var(--text-muted)", opacity: 0.6 }}>
              Crashes will appear here when an attached process crashes
            </span>
          </div>
        ) : (
          crashes.map((c) => <CrashRow key={c.id} crash={c} />)
        )}
      </div>
    </div>
  );
}
