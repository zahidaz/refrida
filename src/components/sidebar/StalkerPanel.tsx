import { useMemo } from "react";
import { useStalkerStore, getFilteredEvents } from "@/stores/stalker.ts";
import { useSessionStore } from "@/stores/session.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";
import { navigateToDisasm } from "@/lib/navigation.ts";

const EVENT_COLORS: Record<string, string> = {
  call: "#3b82f6",
  ret: "#22c55e",
  exec: "#a855f7",
  block: "#f59e0b",
  compile: "#6b7280",
};

const EVENT_LABELS = ["call", "ret", "exec", "block", "compile"];

function EventRow({ event }: { event: { type: string; address: string; target?: string; module: string | null; symbol: string | null } }) {
  return (
    <div
      className="flex items-center gap-1.5 px-3 py-1 hover-row text-[10px] font-mono cursor-pointer"
      onClick={() => navigateToDisasm(event.address)}
      title="Open in disassembler"
    >
      <span
        className="px-1 py-px rounded text-[8px] font-semibold uppercase shrink-0"
        style={{
          color: "white",
          background: EVENT_COLORS[event.type] ?? "var(--text-muted)",
        }}
      >
        {event.type}
      </span>
      <span
        className="shrink-0 cursor-pointer"
        style={{ color: "var(--accent-text)" }}
        onClick={(e) => { e.stopPropagation(); copyToClipboard(event.address); }}
        title="Copy address"
      >
        {event.address}
      </span>
      {event.target && (
        <>
          <i className="fa-solid fa-arrow-right text-[7px]" style={{ color: "var(--text-muted)" }} />
          <span
            className="cursor-pointer"
            style={{ color: "var(--accent-text)" }}
            onClick={(e) => { e.stopPropagation(); copyToClipboard(event.target!); }}
          >
            {event.target}
          </span>
        </>
      )}
      {event.module && (
        <span className="truncate" style={{ color: "var(--text-muted)" }}>
          {event.module}
        </span>
      )}
      {event.symbol && (
        <span className="truncate flex-1" style={{ color: "var(--text-secondary)" }}>
          {event.symbol}
        </span>
      )}
    </div>
  );
}

export default function StalkerPanel() {
  const state = useStalkerStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const filtered = useMemo(() => getFilteredEvents(state), [state]);

  if (!sessionActive) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 px-4">
        <i className="fa-solid fa-route text-xl" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
        <span className="text-[11px]" style={{ color: "var(--text-muted)" }}>
          Attach to a process to use Stalker
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="px-3 py-2 border-b shrink-0 flex flex-col gap-1.5"
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
            Stalker
          </span>
          <span className="text-[9px] px-1.5 py-px rounded-full" style={{ background: "var(--hover-bg)", color: "var(--text-muted)" }}>
            {filtered.length}{state.events.length !== filtered.length ? ` / ${state.events.length}` : ""}
          </span>
          <div className="flex-1" />
          {state.active && (
            <span className="flex items-center gap-1 text-[9px]" style={{ color: "#22c55e" }}>
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#22c55e" }} />
              Tracing
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <input
            type="text"
            value={state.threadId}
            onChange={(e) => state.setThreadId(e.target.value)}
            placeholder="Thread ID (empty = main)"
            disabled={state.active}
            className="flex-1 text-[10px] px-2 py-1 rounded border outline-none font-mono"
            style={{
              background: "var(--bg-primary)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
          />
          {!state.active ? (
            <button
              onClick={state.start}
              className="text-[10px] px-2 py-1 rounded font-medium"
              style={{ color: "white", background: "#22c55e" }}
            >
              Start
            </button>
          ) : (
            <button
              onClick={state.stop}
              className="text-[10px] px-2 py-1 rounded font-medium"
              style={{ color: "white", background: "#ef4444" }}
            >
              Stop
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-1.5">
          {EVENT_LABELS.map((evt) => (
            <label key={evt} className="flex items-center gap-1 text-[9px] cursor-pointer" style={{ color: "var(--text-secondary)" }}>
              <input
                type="checkbox"
                checked={state.eventTypes[evt] ?? false}
                onChange={(e) => state.setEventTypes({ ...state.eventTypes, [evt]: e.target.checked })}
                disabled={state.active}
                className="w-3 h-3"
              />
              <span
                className="px-1 py-px rounded text-[8px] font-semibold uppercase"
                style={{ color: "white", background: EVENT_COLORS[evt] }}
              >
                {evt}
              </span>
            </label>
          ))}
        </div>

        <div className="flex gap-1.5">
          <input
            type="text"
            value={state.filterModule}
            onChange={(e) => state.setFilterModule(e.target.value)}
            placeholder="Filter module..."
            className="flex-1 text-[10px] px-2 py-0.5 rounded border outline-none"
            style={{
              background: "var(--bg-primary)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
          />
          <input
            type="text"
            value={state.filterSearch}
            onChange={(e) => state.setFilterSearch(e.target.value)}
            placeholder="Search..."
            className="flex-1 text-[10px] px-2 py-0.5 rounded border outline-none"
            style={{
              background: "var(--bg-primary)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
          />
        </div>

        <div className="flex gap-1">
          <button
            onClick={state.clear}
            className="text-[9px] px-1.5 py-0.5 rounded"
            style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            Clear
          </button>
          <button
            onClick={state.exportTrace}
            disabled={state.events.length === 0}
            className="text-[9px] px-1.5 py-0.5 rounded disabled:opacity-30"
            style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            Export JSON
          </button>
        </div>

        {state.error && (
          <div className="text-[9px] px-2 py-1 rounded" style={{ color: "#ef4444", background: "rgba(239, 68, 68, 0.08)" }}>
            {state.error}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-1">
            <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
              {state.active ? "Waiting for events..." : "No events captured"}
            </span>
          </div>
        ) : (
          filtered.map((ev, i) => <EventRow key={i} event={ev} />)
        )}
      </div>
    </div>
  );
}
