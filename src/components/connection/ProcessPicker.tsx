import { useState } from "react";
import {
  useProcessesStore,
  getFilteredProcesses,
  getFilteredApplications,
} from "@/stores/processes.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useConnectionStore } from "@/stores/connection.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";
import Modal from "@/components/ui/Modal.tsx";

export default function ProcessPicker() {
  const state = useProcessesStore();
  const connected = useConnectionStore((s) => s.connected);
  const busy = useConnectionStore((s) => s.busy);
  const { spawnTarget, setSpawnTarget, spawnProcess, resumeProcess } =
    useConnectionStore();
  const { attachToProcess, attachedPid } = useSessionStore();
  const setProcessPickerOpen = useLayoutStore((s) => s.setProcessPickerOpen);
  const isMobile = useIsMobile();
  const [killConfirmPid, setKillConfirmPid] = useState<number | null>(null);
  const [tab, setTab] = useState<"processes" | "applications" | "spawn">(
    "processes",
  );

  const processes = getFilteredProcesses(state);
  const applications = getFilteredApplications(state);

  function close() {
    setProcessPickerOpen(false);
  }

  function handleConfirmKill(pid: number) {
    setKillConfirmPid(pid);
    setTimeout(() => setKillConfirmPid(null), 3000);
  }

  async function handleKill(pid: number) {
    setKillConfirmPid(null);
    await state.killProcess(pid);
  }

  function handleAttach(pid: number, name: string) {
    attachToProcess(pid, name);
    close();
  }

  async function handleSpawn() {
    const pid = await spawnProcess();
    if (pid !== null) {
      await attachToProcess(pid, spawnTarget.trim());
      close();
    }
  }

  return (
    <Modal
      onClose={close}
      className="rounded-lg border flex flex-col"
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border)",
        width: isMobile ? "100%" : "min(560px, 100vw)",
        height: isMobile ? "100%" : "70vh",
      }}
    >
      <div
        className="flex items-center gap-2 px-4 py-3 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <span
          className="text-sm font-semibold"
          style={{ color: "var(--text-primary)" }}
        >
          Attach to Process
        </span>
        <div className="flex-1" />
        {state.autoRefresh && <span className="live-indicator">LIVE</span>}
        <button
          onClick={state.toggleAutoRefresh}
          className="text-xs px-1.5 py-0.5 rounded border"
          style={{
            borderColor: state.autoRefresh ? "#22c55e" : "var(--border)",
            color: state.autoRefresh ? "#22c55e" : "var(--text-secondary)",
          }}
        >
          {state.autoRefresh ? "Stop" : "Auto"}
        </button>
        <button
          onClick={state.refreshProcesses}
          disabled={!connected || busy}
          className="text-xs px-1.5 py-0.5 rounded border disabled:opacity-40"
          style={{
            borderColor: "var(--border)",
            color: "var(--text-secondary)",
          }}
        >
          <i className="fa-solid fa-arrows-rotate mr-1" style={{ fontSize: 9 }} />
          Refresh
        </button>
        {!isMobile && (
          <button
            onClick={close}
            className="text-sm px-1"
            style={{ color: "var(--text-muted)" }}
          >
            <i className="fa-solid fa-xmark" />
          </button>
        )}
      </div>

      <div
        className={`flex ${isMobile ? "flex-col gap-2" : "items-center gap-1"} px-4 py-2 border-b shrink-0`}
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-1">
          {(["processes", "applications", "spawn"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`text-xs px-2.5 py-1 rounded ${isMobile ? "flex-1" : ""}`}
              style={
                tab === t
                  ? { background: "var(--accent)", color: "white" }
                  : { color: "var(--text-secondary)" }
              }
            >
              {t === "processes"
                ? "Processes"
                : t === "applications"
                  ? "Apps"
                  : "Spawn"}
            </button>
          ))}
        </div>
        {tab !== "spawn" && (
          <input
            type="text"
            value={state.filterText}
            onChange={(e) => state.setFilterText(e.target.value)}
            placeholder="Filter..."
            className={`text-xs px-2 py-1 rounded border outline-none ${isMobile ? "w-full" : "ml-auto w-44"}`}
            style={{
              background: "var(--bg-input)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
            autoFocus
          />
        )}
      </div>

      <div className="flex-1 flex flex-col overflow-hidden min-h-0">
        {tab === "processes" && (
          <>
            <SortHeader
              sortField={state.sortField}
              sortAsc={state.sortAsc}
              onToggleSort={state.toggleSort}
            />
            <div className="flex-1 overflow-y-auto">
              {processes.map((p) => (
                <div
                  key={p.pid}
                  className="flex items-center px-4 py-1 text-xs cursor-pointer group hover-row"
                  style={{ color: "var(--text-primary)" }}
                  onClick={() => handleAttach(p.pid, p.name)}
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
                        handleKill(p.pid);
                      }}
                      className="text-red-500 text-[10px] px-1 opacity-0 group-hover:opacity-100"
                    >
                      Confirm?
                    </button>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleConfirmKill(p.pid);
                      }}
                      className="text-red-400 text-[10px] px-1 opacity-0 group-hover:opacity-100"
                    >
                      Kill
                    </button>
                  )}
                </div>
              ))}
              {processes.length === 0 && (
                <div
                  className="text-xs px-4 py-6 text-center"
                  style={{ color: "var(--text-muted)" }}
                >
                  {connected ? "No processes found" : "Not connected"}
                </div>
              )}
            </div>
          </>
        )}

        {tab === "applications" && (
          <>
            <SortHeader
              sortField={state.sortField}
              sortAsc={state.sortAsc}
              onToggleSort={state.toggleSort}
              extraColumn="Identifier"
            />
            <div className="flex-1 overflow-y-auto">
              {applications.map((a) => (
                <div
                  key={a.identifier}
                  className="flex items-center px-4 py-1 text-xs cursor-pointer hover-row"
                  style={{ color: "var(--text-primary)" }}
                  onClick={() =>
                    a.pid > 0 && handleAttach(a.pid, a.name)
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
                    className="w-28 text-[10px] truncate"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {a.identifier}
                  </span>
                </div>
              ))}
              {applications.length === 0 && (
                <div
                  className="text-xs px-4 py-6 text-center"
                  style={{ color: "var(--text-muted)" }}
                >
                  {connected ? "No applications found" : "Not connected"}
                </div>
              )}
            </div>
          </>
        )}

        {tab === "spawn" && (
          <div className="px-4 py-4 flex flex-col gap-3">
            <div>
              <label
                className="block text-xs mb-1"
                style={{ color: "var(--text-secondary)" }}
              >
                Bundle Identifier / Binary Path
              </label>
              <input
                type="text"
                value={spawnTarget}
                onChange={(e) => setSpawnTarget(e.target.value)}
                placeholder="com.example.app or /usr/bin/target"
                className="text-xs px-2.5 py-1.5 rounded border outline-none w-full"
                style={{
                  background: "var(--bg-input)",
                  borderColor: "var(--border)",
                  color: "var(--text-primary)",
                }}
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter" && spawnTarget.trim()) handleSpawn();
                }}
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleSpawn}
                disabled={!spawnTarget.trim() || !connected}
                className="text-xs px-3 py-1.5 rounded font-medium text-white disabled:opacity-40"
                style={{ background: "var(--accent)" }}
              >
                Spawn & Attach
              </button>
              {attachedPid && (
                <button
                  onClick={() => {
                    resumeProcess(attachedPid);
                    close();
                  }}
                  className="text-xs px-3 py-1.5 rounded font-medium text-white bg-green-600 hover:bg-green-700"
                >
                  Resume PID {attachedPid}
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

function SortHeader({
  sortField,
  sortAsc,
  onToggleSort,
  extraColumn,
}: {
  sortField: string;
  sortAsc: boolean;
  onToggleSort: (field: "pid" | "name") => void;
  extraColumn?: string;
}) {
  return (
    <div
      className="flex items-center px-4 py-1 text-xs border-b shrink-0"
      style={{
        borderColor: "var(--border)",
        color: "var(--text-muted)",
      }}
    >
      <span
        className="w-16 cursor-pointer"
        onClick={() => onToggleSort("pid")}
      >
        PID
        <span
          className={`sort-arrow ${sortField === "pid" ? (sortAsc ? "asc" : "desc") : ""}`}
        />
      </span>
      <span
        className="flex-1 cursor-pointer"
        onClick={() => onToggleSort("name")}
      >
        Name
        <span
          className={`sort-arrow ${sortField === "name" ? (sortAsc ? "asc" : "desc") : ""}`}
        />
      </span>
      {extraColumn && <span className="w-28">{extraColumn}</span>}
    </div>
  );
}
