import { useState } from "react";
import {
  useProcessesStore,
  getFilteredProcesses,
  getFilteredApplications,
} from "@/stores/processes.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useConnectionStore } from "@/stores/connection.ts";
import SpawnBar from "@/components/connection/SpawnBar.tsx";

export default function Sidebar() {
  const state = useProcessesStore();
  const connected = useConnectionStore((s) => s.connected);
  const busy = useConnectionStore((s) => s.busy);
  const attachToProcess = useSessionStore((s) => s.attachToProcess);
  const [killConfirmPid, setKillConfirmPid] = useState<number | null>(null);

  const processes = getFilteredProcesses(state);
  const applications = getFilteredApplications(state);

  function confirmKill(pid: number) {
    setKillConfirmPid(pid);
    setTimeout(() => setKillConfirmPid(null), 3000);
  }

  async function doKill(pid: number) {
    setKillConfirmPid(null);
    await state.killProcess(pid);
  }

  return (
    <div
      className="flex flex-col h-full border-r"
      style={{
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      <div
        className="flex items-center gap-1 px-2 py-1 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <button
          onClick={() => state.setActiveTab("processes")}
          className={`text-xs px-2 py-0.5 rounded ${state.activeTab === "processes" ? "bg-cyan-600 text-white" : ""}`}
          style={
            state.activeTab !== "processes"
              ? { color: "var(--text-secondary)" }
              : undefined
          }
        >
          Processes
        </button>
        <button
          onClick={() => state.setActiveTab("applications")}
          className={`text-xs px-2 py-0.5 rounded ${state.activeTab === "applications" ? "bg-cyan-600 text-white" : ""}`}
          style={
            state.activeTab !== "applications"
              ? { color: "var(--text-secondary)" }
              : undefined
          }
        >
          Applications
        </button>
        <div className="flex-1" />
        {state.autoRefresh && <span className="live-indicator">LIVE</span>}
        <button
          onClick={state.toggleAutoRefresh}
          className="text-xs px-1.5 py-0.5 rounded border"
          style={{
            borderColor: state.autoRefresh ? "#22c55e" : "var(--border)",
            color: state.autoRefresh
              ? "#22c55e"
              : "var(--text-secondary)",
          }}
          title="Auto-refresh"
        >
          {state.autoRefresh ? "Stop" : "Auto"}
        </button>
        <button
          onClick={state.refreshProcesses}
          disabled={!connected || busy}
          className="text-xs px-1.5 py-0.5 rounded border"
          style={{
            borderColor: "var(--border)",
            color: "var(--text-secondary)",
          }}
        >
          Refresh
        </button>
      </div>

      <div className="px-2 py-1">
        <input
          type="text"
          value={state.filterText}
          onChange={(e) => state.setFilterText(e.target.value)}
          placeholder="Filter..."
          className="text-xs px-2 py-1 rounded border outline-none w-full"
          style={{
            background: "var(--bg-input)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
          }}
        />
      </div>

      {state.activeTab === "processes" && (
        <>
          <div
            className="flex items-center px-2 py-0.5 text-xs border-b"
            style={{
              borderColor: "var(--border)",
              color: "var(--text-muted)",
            }}
          >
            <span
              className="w-16 cursor-pointer"
              onClick={() => state.toggleSort("pid")}
            >
              PID{" "}
              <span
                className={`sort-arrow ${state.sortField === "pid" ? (state.sortAsc ? "asc" : "desc") : ""}`}
              />
            </span>
            <span
              className="flex-1 cursor-pointer"
              onClick={() => state.toggleSort("name")}
            >
              Name{" "}
              <span
                className={`sort-arrow ${state.sortField === "name" ? (state.sortAsc ? "asc" : "desc") : ""}`}
              />
            </span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {processes.map((p) => (
              <div
                key={p.pid}
                className="flex items-center px-2 py-0.5 text-xs cursor-pointer group"
                style={{ color: "var(--text-primary)" }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "var(--hover-bg)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "transparent")
                }
                onClick={() => attachToProcess(p.pid, p.name)}
              >
                <span
                  className="w-16 font-mono"
                  style={{ color: "var(--text-muted)" }}
                >
                  {p.pid}
                </span>
                <span className="flex-1 truncate">{p.name}</span>
                {killConfirmPid === p.pid ? (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      doKill(p.pid);
                    }}
                    className="text-red-500 text-[10px] px-1 opacity-0 group-hover:opacity-100"
                  >
                    Confirm?
                  </button>
                ) : (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      confirmKill(p.pid);
                    }}
                    className="text-red-400 text-[10px] px-1 opacity-0 group-hover:opacity-100"
                  >
                    Kill
                  </button>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {state.activeTab === "applications" && (
        <>
          <div
            className="flex items-center px-2 py-0.5 text-xs border-b"
            style={{
              borderColor: "var(--border)",
              color: "var(--text-muted)",
            }}
          >
            <span
              className="w-16 cursor-pointer"
              onClick={() => state.toggleSort("pid")}
            >
              PID{" "}
              <span
                className={`sort-arrow ${state.sortField === "pid" ? (state.sortAsc ? "asc" : "desc") : ""}`}
              />
            </span>
            <span
              className="flex-1 cursor-pointer"
              onClick={() => state.toggleSort("name")}
            >
              Name{" "}
              <span
                className={`sort-arrow ${state.sortField === "name" ? (state.sortAsc ? "asc" : "desc") : ""}`}
              />
            </span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {applications.map((a) => (
              <div
                key={a.identifier}
                className="flex items-center px-2 py-0.5 text-xs cursor-pointer"
                style={{ color: "var(--text-primary)" }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "var(--hover-bg)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "transparent")
                }
                onClick={() =>
                  a.pid > 0 && attachToProcess(a.pid, a.name)
                }
              >
                <span
                  className="w-16 font-mono"
                  style={{ color: "var(--text-muted)" }}
                >
                  {a.pid || "-"}
                </span>
                <span className="flex-1 truncate">{a.name}</span>
                <span
                  className="text-[10px] truncate max-w-24"
                  style={{ color: "var(--text-muted)" }}
                >
                  {a.identifier}
                </span>
              </div>
            ))}
          </div>
        </>
      )}

      {connected && <SpawnBar />}
    </div>
  );
}
