import { useConnectionStore } from "@/stores/connection.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useProcessesStore } from "@/stores/processes.ts";
import { useConsoleStore } from "@/stores/console.ts";
import { useThemeStore } from "@/stores/theme.ts";

export default function Navbar() {
  const {
    serverUrl,
    setServerUrl,
    tls,
    setTls,
    authToken,
    setAuthToken,
    connected,
    busy,
    deviceInfo,
    connect,
    disconnect,
  } = useConnectionStore();
  const sessionReset = useSessionStore((s) => s.reset);
  const processesReset = useProcessesStore((s) => s.reset);
  const setProcesses = useProcessesStore((s) => s.setProcesses);
  const refreshApplications = useProcessesStore((s) => s.refreshApplications);
  const appendConsole = useConsoleStore((s) => s.append);
  const { dark, toggle: toggleTheme } = useThemeStore();

  async function handleConnect() {
    const processes = await connect();
    if (processes) {
      setProcesses(processes);
      refreshApplications();
    }
  }

  function handleDisconnect() {
    sessionReset();
    processesReset();
    disconnect();
    appendConsole("Disconnected.", "system");
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !connected && !busy) {
      handleConnect();
    }
  }

  return (
    <nav
      className="flex items-center gap-2 px-3 py-1.5 border-b"
      style={{
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      <img
        src="https://frida.re/img/logotype.svg"
        alt="Frida"
        className="h-5 opacity-80"
      />
      <span
        className="text-sm font-semibold mr-2"
        style={{ color: "var(--text-primary)" }}
      >
        Web
      </span>

      <input
        type="text"
        value={serverUrl}
        onChange={(e) => setServerUrl(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="host:port"
        disabled={connected}
        className="text-xs px-2 py-1 rounded border outline-none w-44"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      />

      <select
        value={tls}
        onChange={(e) => setTls(e.target.value)}
        disabled={connected}
        className="text-xs px-1.5 py-1 rounded border outline-none"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      >
        <option value="disabled">TLS Off</option>
        <option value="enabled">TLS On</option>
        <option value="auto">TLS Auto</option>
      </select>

      <input
        type="password"
        value={authToken}
        onChange={(e) => setAuthToken(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Token"
        disabled={connected}
        className="text-xs px-2 py-1 rounded border outline-none w-20"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      />

      {!connected ? (
        <button
          onClick={handleConnect}
          disabled={busy}
          className={`text-xs px-3 py-1 rounded font-medium text-white bg-cyan-600 hover:bg-cyan-700 ${busy ? "loading" : ""}`}
        >
          Connect
        </button>
      ) : (
        <button
          onClick={handleDisconnect}
          className="text-xs px-3 py-1 rounded font-medium text-white bg-red-600 hover:bg-red-700"
        >
          Disconnect
        </button>
      )}

      {connected && deviceInfo && (
        <DeviceBadges info={deviceInfo} />
      )}

      <div className="flex-1" />

      <button
        onClick={toggleTheme}
        className="flex items-center justify-center w-7 h-7 rounded border cursor-pointer"
        style={{
          borderColor: "var(--border)",
          color: "var(--text-secondary)",
          background: "transparent",
        }}
        title="Toggle theme"
      >
        <i className={`fa-solid ${dark ? "fa-sun" : "fa-moon"}`} />
      </button>
    </nav>
  );
}

function DeviceBadges({ info }: { info: Record<string, unknown> }) {
  const osName = info.os
    ? String((info.os as Record<string, unknown>)?.name ?? "")
    : "";
  const arch = info.arch ? String(info.arch) : "";
  const name = info.name ? String(info.name) : "";

  return (
    <div className="flex items-center gap-1 ml-1">
      {osName && <span className="device-badge">{osName}</span>}
      {arch && <span className="device-badge">{arch}</span>}
      {name && <span className="device-badge">{name}</span>}
    </div>
  );
}
