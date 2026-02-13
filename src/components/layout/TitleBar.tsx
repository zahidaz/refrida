import { useConnectionStore } from "@/stores/connection.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useProcessesStore } from "@/stores/processes.ts";
import { useThemeStore } from "@/stores/theme.ts";
import { useConsoleStore } from "@/stores/console.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import MenuBar from "./MenuBar.tsx";
import DeviceBadges from "@/components/ui/DeviceBadges.tsx";
import type { MonacoEditor } from "@/components/editor/ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
}

export default function TitleBar({ editorRef }: Props) {
  const {
    connected,
    deviceInfo,
    serverUrl,
    busy,
    disconnect,
  } = useConnectionStore();
  const sessionReset = useSessionStore((s) => s.reset);
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const detachSession = useSessionStore((s) => s.detachSession);
  const sessionInfoText = useSessionStore((s) => s.sessionInfoText);
  const processesReset = useProcessesStore((s) => s.reset);
  const appendConsole = useConsoleStore((s) => s.append);
  const { dark, toggle: toggleTheme } = useThemeStore();
  const {
    setConnectionDialogOpen,
    setProcessPickerOpen,
  } = useLayoutStore();

  function handleDisconnect() {
    sessionReset();
    processesReset();
    disconnect();
    appendConsole("Disconnected.", "system");
  }

  function handleConnect() {
    setConnectionDialogOpen(true);
  }

  return (
    <div
      className="flex items-center gap-1 px-2 py-0.5 border-b"
      style={{
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      <span className="text-sm font-bold font-mono select-none mr-1">
        <span style={{ color: "var(--accent-text)" }}>re</span>
        <span style={{ color: "var(--text-primary)" }}>Frida</span>
      </span>

      <MenuBar editorRef={editorRef} />

      <div className="flex-1" />

      {sessionActive && (
        <>
          <span
            className="text-[10px] px-1"
            style={{ color: "var(--text-muted)" }}
          >
            {sessionInfoText}
          </span>
          <button
            onClick={detachSession}
            className="text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5"
            style={{
              color: "#d97706",
              border: "1px solid rgba(217, 119, 6, 0.3)",
            }}
            title="Detach from process"
          >
            <i className="fa-solid fa-link-slash" style={{ fontSize: 9 }} />
            Detach
          </button>
        </>
      )}

      <button
        onClick={() => setProcessPickerOpen(true)}
        disabled={!connected}
        className="text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 disabled:opacity-30"
        style={{
          color: "var(--accent-text)",
          border: "1px solid var(--accent)",
          background: "var(--accent-soft)",
        }}
        title="Attach to Process"
      >
        <i className="fa-solid fa-crosshairs" style={{ fontSize: 10 }} />
        Attach
      </button>

      <div
        className="w-px h-4 mx-1"
        style={{ background: "var(--border)" }}
      />

      {connected ? (
        <>
          <span
            className="text-xs flex items-center gap-1.5 px-2 py-0.5 rounded"
            style={{
              color: "#22c55e",
              background: "rgba(34, 197, 94, 0.08)",
            }}
          >
            <span
              className="inline-block w-1.5 h-1.5 rounded-full"
              style={{ background: "#22c55e" }}
            />
            {serverUrl}
          </span>
          {deviceInfo && <DeviceBadges info={deviceInfo} />}
          <button
            onClick={handleDisconnect}
            disabled={busy}
            className={`text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 ${busy ? "loading" : ""}`}
            style={{
              color: "#ef4444",
              border: "1px solid rgba(239, 68, 68, 0.3)",
            }}
            title="Disconnect"
          >
            <i className="fa-solid fa-plug-circle-xmark" style={{ fontSize: 9 }} />
            Disconnect
          </button>
        </>
      ) : (
        <button
          onClick={handleConnect}
          disabled={busy}
          className={`text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 ${busy ? "loading" : ""}`}
          style={{ color: "white", background: "var(--accent)" }}
          title="Connect"
        >
          <i className="fa-solid fa-plug" style={{ fontSize: 9 }} />
          Connect
        </button>
      )}

      <div
        className="w-px h-4 mx-1"
        style={{ background: "var(--border)" }}
      />

      <button
        onClick={toggleTheme}
        className="titlebar-btn"
        style={{ color: "var(--text-secondary)" }}
        title="Toggle Theme"
      >
        <i className={`fa-solid ${dark ? "fa-sun" : "fa-moon"}`} style={{ fontSize: 11 }} />
      </button>
    </div>
  );
}
