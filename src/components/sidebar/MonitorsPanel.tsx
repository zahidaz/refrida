import { useMonitorsStore, type NetworkEvent, type FileEvent } from "@/stores/monitors.ts";
import { useSessionStore } from "@/stores/session.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

function previewToAscii(preview: number[]): string {
  return preview.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")).join("");
}

function formatTs(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

const EVENT_COLORS: Record<string, string> = {
  connect: "#60a5fa",
  send: "#f59e0b",
  sendto: "#f59e0b",
  recv: "#34d399",
  recvfrom: "#34d399",
  open: "#60a5fa",
  read: "#34d399",
  write: "#f59e0b",
  close: "#ef4444",
};

function EventBadge({ event }: { event: string }) {
  return (
    <span
      className="text-[9px] font-mono font-bold px-1 py-0.5 rounded shrink-0"
      style={{
        color: EVENT_COLORS[event] ?? "var(--text-muted)",
        background: `${EVENT_COLORS[event] ?? "var(--text-muted)"}15`,
      }}
    >
      {event.toUpperCase()}
    </span>
  );
}

function NetworkRow({ ev }: { ev: NetworkEvent }) {
  return (
    <div className="flex items-start gap-2 px-3 py-1 text-[10px] hover-row font-mono">
      <span className="shrink-0" style={{ color: "var(--text-muted)", width: 72 }}>{formatTs(ev.ts)}</span>
      <EventBadge event={ev.event} />
      <span className="shrink-0" style={{ color: "var(--text-muted)" }}>fd:{ev.fd}</span>
      {ev.ip && (
        <span
          className="shrink-0 cursor-pointer"
          style={{ color: "var(--text-primary)" }}
          onClick={() => copyToClipboard(`${ev.ip}:${ev.port}`)}
        >
          {ev.ip}:{ev.port}
        </span>
      )}
      {ev.length !== undefined && (
        <span className="shrink-0" style={{ color: "var(--text-muted)" }}>{ev.length}B</span>
      )}
      {ev.preview && ev.preview.length > 0 && (
        <span className="truncate" style={{ color: "var(--json-string)" }}>
          {previewToAscii(ev.preview)}
        </span>
      )}
    </div>
  );
}

function FileRow({ ev }: { ev: FileEvent }) {
  return (
    <div className="flex items-start gap-2 px-3 py-1 text-[10px] hover-row font-mono">
      <span className="shrink-0" style={{ color: "var(--text-muted)", width: 72 }}>{formatTs(ev.ts)}</span>
      <EventBadge event={ev.event} />
      <span className="shrink-0" style={{ color: "var(--text-muted)" }}>fd:{ev.fd}</span>
      {ev.path && (
        <span
          className="truncate cursor-pointer"
          style={{ color: "var(--text-primary)" }}
          onClick={() => copyToClipboard(ev.path!)}
          title={ev.path}
        >
          {ev.path}
        </span>
      )}
      {ev.length !== undefined && (
        <span className="shrink-0" style={{ color: "var(--text-muted)" }}>{ev.length}B</span>
      )}
    </div>
  );
}

export default function MonitorsPanel() {
  const state = useMonitorsStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);

  if (!sessionActive) {
    return (
      <div className="flex-1 flex items-center justify-center text-xs" style={{ color: "var(--text-muted)" }}>
        Attach to a process to use monitors
      </div>
    );
  }

  const isNetwork = state.activeTab === "network";
  const events = isNetwork ? state.networkEvents : state.fileEvents;
  const active = isNetwork ? state.networkActive : state.fileActive;
  const error = isNetwork ? state.networkError : state.fileError;

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-1.5 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
          Monitors
        </span>
        <div className="flex-1" />
        <div className="flex gap-0.5">
          {(["network", "files"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => state.setActiveTab(tab)}
              className="text-[10px] px-2 py-0.5 rounded icon-btn"
              style={{
                background: state.activeTab === tab ? "var(--accent)" : "transparent",
                color: state.activeTab === tab ? "white" : "var(--text-muted)",
              }}
            >
              {tab === "network" ? "Network" : "File I/O"}
            </button>
          ))}
        </div>
      </div>

      <div
        className="flex items-center gap-1.5 px-3 py-1.5 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        {active ? (
          <button
            onClick={() => isNetwork ? state.stopNetwork() : state.stopFile()}
            className="text-[10px] px-2 py-0.5 rounded font-medium"
            style={{ color: "#ef4444", border: "1px solid rgba(239,68,68,0.25)" }}
          >
            <i className="fa-solid fa-stop" style={{ fontSize: 8 }} /> Stop
          </button>
        ) : (
          <button
            onClick={() => isNetwork ? state.startNetwork() : state.startFile()}
            className="text-[10px] px-2 py-0.5 rounded font-medium text-white"
            style={{ background: "#16a34a" }}
          >
            <i className="fa-solid fa-play" style={{ fontSize: 8 }} /> Start
          </button>
        )}
        <button
          onClick={() => isNetwork ? state.clearNetwork() : state.clearFile()}
          className="text-[10px] px-1.5 py-0.5 rounded border icon-btn"
          style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
          title="Clear"
        >
          <i className="fa-solid fa-trash" style={{ fontSize: 8 }} />
        </button>
        <div className="flex-1" />
        <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>
          {events.length} events
        </span>
        {active && (
          <span className="text-[9px] flex items-center gap-1" style={{ color: "#16a34a" }}>
            <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: "#16a34a" }} />
            Live
          </span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto" style={{ background: "var(--bg-primary)" }}>
        {error && (
          <div className="text-xs px-3 py-3 text-center" style={{ color: "#ef4444" }}>{error}</div>
        )}

        {events.length > 0 ? (
          isNetwork
            ? (events as NetworkEvent[]).map((ev, i) => <NetworkRow key={i} ev={ev} />)
            : (events as FileEvent[]).map((ev, i) => <FileRow key={i} ev={ev} />)
        ) : !active ? (
          <div className="flex-1 flex items-center justify-center px-6 py-8">
            <div className="text-center" style={{ color: "var(--text-muted)" }}>
              <i
                className={`fa-solid ${isNetwork ? "fa-network-wired" : "fa-file"} text-2xl mb-3 block`}
                style={{ opacity: 0.3 }}
              />
              <p className="text-xs mb-2">
                {isNetwork
                  ? "Monitor network activity (connect, send, recv)"
                  : "Monitor file operations (open, read, write, close)"}
              </p>
              <p className="text-[10px]">
                Click Start to begin capturing events.
              </p>
            </div>
          </div>
        ) : (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            Waiting for events...
          </div>
        )}
      </div>
    </div>
  );
}
