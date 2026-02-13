import { useEffect, useState, useMemo } from "react";
import { useProcessInfoStore, type ThreadInfo, type EnvVar } from "@/stores/processInfo.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useConnectionStore } from "@/stores/connection.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

type Section = "overview" | "threads" | "env" | "operations";

const SECTIONS: Array<{ id: Section; label: string; icon: string }> = [
  { id: "overview", label: "Overview", icon: "fa-circle-info" },
  { id: "threads", label: "Threads", icon: "fa-layer-group" },
  { id: "env", label: "Environment", icon: "fa-leaf" },
  { id: "operations", label: "Operations", icon: "fa-gears" },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function InfoRow({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="flex items-center py-1.5 px-4 hover-row">
      <span className="text-[11px] w-40 shrink-0" style={{ color: "var(--text-muted)" }}>{label}</span>
      <span
        className={`text-[11px] flex-1 ${mono ? "font-mono" : ""}`}
        style={{ color: "var(--text-primary)" }}
      >
        {value}
      </span>
      <button
        className="text-[9px] px-1 shrink-0 icon-btn opacity-0 group-hover:opacity-60"
        style={{ color: "var(--text-muted)" }}
        onClick={() => copyToClipboard(String(value))}
        title="Copy"
      >
        <i className="fa-solid fa-copy" style={{ fontSize: 9 }} />
      </button>
    </div>
  );
}

function OverviewSection() {
  const { info, loading, error, fetchInfo } = useProcessInfoStore();

  useEffect(() => {
    if (!info && !loading) fetchInfo();
  }, [info, loading, fetchInfo]);

  if (loading) {
    return <div className="text-xs p-4" style={{ color: "var(--text-muted)" }}>Loading process info...</div>;
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="text-[11px] mb-2" style={{ color: "#ef4444" }}>{error}</div>
        <button onClick={fetchInfo} className="text-[10px] px-2 py-1 rounded" style={{ color: "var(--accent-text)", border: "1px solid var(--accent)" }}>
          Retry
        </button>
      </div>
    );
  }

  if (!info) return null;

  return (
    <div>
      <div className="flex items-center gap-2 px-4 py-2 border-b" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Process Details</span>
        <div className="flex-1" />
        <button onClick={fetchInfo} className="text-[9px] px-1.5 py-0.5 rounded icon-btn" style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}>
          Refresh
        </button>
      </div>
      <div className="[&>div]:group">
        <InfoRow label="PID" value={info.pid} mono />
        <InfoRow label="Architecture" value={info.arch} />
        <InfoRow label="Platform" value={info.platform} />
        <InfoRow label="Page Size" value={`${info.pageSize} bytes`} />
        <InfoRow label="Pointer Size" value={`${info.pointerSize} bytes (${info.pointerSize * 8}-bit)`} />
        <InfoRow label="Current Thread" value={info.currentThreadId} mono />
      </div>
      <div className="flex items-center gap-2 px-4 py-2 border-b border-t mt-2" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Main Module</span>
      </div>
      <div className="[&>div]:group">
        <InfoRow label="Name" value={info.mainModule.name} />
        <InfoRow label="Base Address" value={info.mainModule.base} mono />
        <InfoRow label="Size" value={formatBytes(info.mainModule.size)} />
        <InfoRow label="Path" value={info.mainModule.path} />
      </div>
      <div className="flex items-center gap-2 px-4 py-2 border-b border-t mt-2" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Statistics</span>
      </div>
      <div className="[&>div]:group">
        <InfoRow label="Threads" value={info.threadCount} />
        <InfoRow label="Modules" value={info.moduleCount} />
        <InfoRow label="Memory Ranges" value={info.rangeCount} />
        <InfoRow label="Total Mapped Memory" value={formatBytes(info.totalMappedSize)} />
      </div>
    </div>
  );
}

function ThreadRow({ thread }: { thread: ThreadInfo }) {
  const stateColor = thread.state === "running" ? "#22c55e"
    : thread.state === "stopped" ? "#ef4444"
    : thread.state === "waiting" ? "#f59e0b"
    : "var(--text-muted)";

  return (
    <div className="flex items-center gap-3 px-4 py-1.5 hover-row text-[11px]">
      <span className="font-mono w-16 shrink-0" style={{ color: "var(--text-primary)" }}>{thread.id}</span>
      <span className="px-1.5 py-px rounded text-[9px] font-medium shrink-0" style={{ color: stateColor, background: `${stateColor}15` }}>
        {thread.state}
      </span>
      {thread.pc && (
        <span
          className="font-mono cursor-pointer truncate"
          style={{ color: "var(--accent-text)" }}
          onClick={() => copyToClipboard(thread.pc!)}
          title="Copy PC"
        >
          PC: {thread.pc}
        </span>
      )}
      <div className="flex-1" />
      {thread.sp && (
        <span className="font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>
          SP: {thread.sp}
        </span>
      )}
    </div>
  );
}

function ThreadsSection() {
  const { threads, loadingThreads, fetchThreads } = useProcessInfoStore();

  useEffect(() => {
    if (threads.length === 0 && !loadingThreads) fetchThreads();
  }, [threads.length, loadingThreads, fetchThreads]);

  return (
    <div>
      <div className="flex items-center gap-2 px-4 py-2 border-b" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
          Threads
          <span className="ml-1.5 text-[9px] font-normal px-1.5 py-px rounded-full" style={{ background: "var(--hover-bg)", color: "var(--text-muted)" }}>
            {threads.length}
          </span>
        </span>
        <div className="flex-1" />
        <button onClick={fetchThreads} disabled={loadingThreads} className={`text-[9px] px-1.5 py-0.5 rounded icon-btn ${loadingThreads ? "loading" : ""}`} style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}>
          Refresh
        </button>
      </div>
      <div className="flex items-center gap-3 px-4 py-1 text-[9px] font-semibold border-b" style={{ borderColor: "var(--border)", color: "var(--text-muted)" }}>
        <span className="w-16 shrink-0">ID</span>
        <span className="w-16 shrink-0">State</span>
        <span className="flex-1">PC</span>
        <span>SP</span>
      </div>
      {loadingThreads && threads.length === 0 ? (
        <div className="text-xs p-4" style={{ color: "var(--text-muted)" }}>Loading threads...</div>
      ) : (
        threads.map((t) => <ThreadRow key={t.id} thread={t} />)
      )}
    </div>
  );
}

function EnvRow({ env }: { env: EnvVar }) {
  return (
    <div className="flex items-center gap-2 px-4 py-1 hover-row text-[11px]">
      <span className="font-mono font-medium w-48 shrink-0 truncate" style={{ color: "var(--accent-text)" }}>{env.key}</span>
      <span className="font-mono flex-1 truncate" style={{ color: "var(--text-secondary)" }}>{env.value}</span>
      <button
        className="text-[9px] px-1 shrink-0 icon-btn"
        style={{ color: "var(--text-muted)" }}
        onClick={() => copyToClipboard(`${env.key}=${env.value}`)}
        title="Copy"
      >
        <i className="fa-solid fa-copy" style={{ fontSize: 9 }} />
      </button>
    </div>
  );
}

function EnvSection() {
  const { envVars, loadingEnv, fetchEnvVars, envFilter, setEnvFilter } = useProcessInfoStore();

  useEffect(() => {
    if (envVars.length === 0 && !loadingEnv) fetchEnvVars();
  }, [envVars.length, loadingEnv, fetchEnvVars]);

  const filtered = useMemo(() => {
    if (!envFilter) return envVars;
    const q = envFilter.toLowerCase();
    return envVars.filter((e) => e.key.toLowerCase().includes(q) || e.value.toLowerCase().includes(q));
  }, [envVars, envFilter]);

  return (
    <div>
      <div className="flex items-center gap-2 px-4 py-2 border-b" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
          Environment Variables
          <span className="ml-1.5 text-[9px] font-normal px-1.5 py-px rounded-full" style={{ background: "var(--hover-bg)", color: "var(--text-muted)" }}>
            {filtered.length}{envFilter ? ` / ${envVars.length}` : ""}
          </span>
        </span>
        <div className="flex-1" />
        <button onClick={fetchEnvVars} disabled={loadingEnv} className={`text-[9px] px-1.5 py-0.5 rounded icon-btn ${loadingEnv ? "loading" : ""}`} style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}>
          Refresh
        </button>
      </div>
      <div className="px-4 py-1.5 border-b" style={{ borderColor: "var(--border)" }}>
        <input
          type="text"
          value={envFilter}
          onChange={(e) => setEnvFilter(e.target.value)}
          placeholder="Filter environment variables..."
          className="text-[11px] px-2 py-1 rounded border outline-none w-full"
          style={{ background: "var(--bg-primary)", borderColor: "var(--border)", color: "var(--text-primary)" }}
        />
      </div>
      {loadingEnv && envVars.length === 0 ? (
        <div className="text-xs p-4" style={{ color: "var(--text-muted)" }}>Loading environment...</div>
      ) : filtered.length === 0 ? (
        <div className="text-xs p-4 text-center" style={{ color: "var(--text-muted)" }}>
          {envFilter ? "No matching variables" : "No environment variables found"}
        </div>
      ) : (
        filtered.map((e) => <EnvRow key={e.key} env={e} />)
      )}
    </div>
  );
}

function OperationsSection() {
  const { killProcess, spawnProcess } = useProcessInfoStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const connected = useConnectionStore((s) => s.connected);
  const [spawnProgram, setSpawnProgram] = useState("");
  const [confirmKill, setConfirmKill] = useState(false);

  return (
    <div>
      <div className="px-4 py-2 border-b" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Operations</span>
      </div>

      <div className="p-4 flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] font-medium" style={{ color: "var(--text-primary)" }}>Kill Process</span>
          <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>Terminate the currently attached process</span>
          {confirmKill ? (
            <div className="flex gap-1.5">
              <button
                onClick={() => { killProcess(); setConfirmKill(false); }}
                className="text-[10px] px-3 py-1 rounded font-medium"
                style={{ color: "white", background: "#ef4444" }}
              >
                Confirm Kill
              </button>
              <button
                onClick={() => setConfirmKill(false)}
                className="text-[10px] px-3 py-1 rounded"
                style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmKill(true)}
              disabled={!sessionActive}
              className="text-[10px] px-3 py-1 rounded font-medium self-start disabled:opacity-30"
              style={{ color: "#ef4444", border: "1px solid rgba(239, 68, 68, 0.3)" }}
            >
              <i className="fa-solid fa-skull-crossbones mr-1.5" style={{ fontSize: 9 }} />
              Kill Process
            </button>
          )}
        </div>

        <div className="border-t pt-4" style={{ borderColor: "var(--border)" }}>
          <span className="text-[11px] font-medium" style={{ color: "var(--text-primary)" }}>Spawn &amp; Resume</span>
          <span className="text-[9px] block mb-1.5" style={{ color: "var(--text-muted)" }}>Spawn a new process and resume it</span>
          <div className="flex gap-1.5">
            <input
              type="text"
              value={spawnProgram}
              onChange={(e) => setSpawnProgram(e.target.value)}
              placeholder="Program path or bundle ID"
              className="flex-1 text-[11px] px-2 py-1 rounded border outline-none"
              style={{ background: "var(--bg-primary)", borderColor: "var(--border)", color: "var(--text-primary)" }}
            />
            <button
              onClick={() => { if (spawnProgram.trim()) spawnProcess(spawnProgram.trim()); }}
              disabled={!connected || !spawnProgram.trim()}
              className="text-[10px] px-3 py-1 rounded font-medium disabled:opacity-30"
              style={{ color: "white", background: "var(--accent)" }}
            >
              Spawn
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ProcessInfoTab() {
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const { activeSection, setActiveSection } = useProcessInfoStore();

  if (!sessionActive) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2">
        <i className="fa-solid fa-circle-info text-2xl" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
        <span className="text-xs" style={{ color: "var(--text-muted)" }}>Attach to a process to view info</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--bg-primary)" }}>
      <div className="flex border-b shrink-0" style={{ borderColor: "var(--border)" }}>
        {SECTIONS.map((s) => (
          <button
            key={s.id}
            onClick={() => setActiveSection(s.id)}
            className="flex items-center gap-1.5 px-3 py-2 text-[11px] border-b-2"
            style={{
              color: activeSection === s.id ? "var(--accent-text)" : "var(--text-muted)",
              borderColor: activeSection === s.id ? "var(--accent)" : "transparent",
            }}
          >
            <i className={`fa-solid ${s.icon}`} style={{ fontSize: 10 }} />
            {s.label}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto">
        {activeSection === "overview" && <OverviewSection />}
        {activeSection === "threads" && <ThreadsSection />}
        {activeSection === "env" && <EnvSection />}
        {activeSection === "operations" && <OperationsSection />}
      </div>
    </div>
  );
}
