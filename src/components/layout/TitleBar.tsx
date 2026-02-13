import { useConnectionStore } from "@/stores/connection.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useThemeStore } from "@/stores/theme.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";
import MenuBar from "./MenuBar.tsx";
import DeviceBadges from "@/components/ui/DeviceBadges.tsx";
import type { MonacoEditor } from "@/components/editor/ScriptEditor.tsx";

interface Props {
  editorRef: React.RefObject<MonacoEditor | null>;
  onSave: () => void;
}

export default function TitleBar({ editorRef, onSave }: Props) {
  const {
    connected,
    deviceInfo,
    serverUrl,
    busy,
    disconnect,
  } = useConnectionStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const detachSession = useSessionStore((s) => s.detachSession);
  const sessionInfoText = useSessionStore((s) => s.sessionInfoText);
  const { dark, toggle: toggleTheme } = useThemeStore();
  const {
    setConnectionDialogOpen,
    setProcessPickerOpen,
    setCommandPaletteOpen,
    setAboutOpen,
  } = useLayoutStore();
  const isMobile = useIsMobile();

  function handleConnect() {
    setConnectionDialogOpen(true);
  }

  return (
    <div
      className="flex items-center gap-1 px-2 py-0.5 border-b overflow-visible relative z-50"
      style={{
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      <button
        onClick={() => setAboutOpen(true)}
        className="text-sm font-bold font-mono select-none shrink-0 mr-1 cursor-pointer bg-transparent border-none p-0"
        title="About reFrida"
      >
        <span style={{ color: "var(--accent-text)" }}>re</span>
        <span style={{ color: "var(--text-primary)" }}>Frida</span>
        <span
          className="text-[8px] font-medium ml-1 px-1 py-px rounded-full align-top"
          style={{
            color: "var(--text-muted)",
            border: "1px solid var(--border)",
          }}
        >
          beta
        </span>
      </button>

      {isMobile ? (
        <button
          onClick={() => setCommandPaletteOpen(true)}
          className="titlebar-btn shrink-0"
          style={{ color: "var(--text-secondary)" }}
          title="Menu"
        >
          <i className="fa-solid fa-bars" style={{ fontSize: 13 }} />
        </button>
      ) : (
        <MenuBar editorRef={editorRef} onSave={onSave} />
      )}

      <div className="flex-1 min-w-0" />

      {!isMobile && sessionActive && (
        <>
          <span
            className="text-[10px] px-1 truncate max-w-40"
            style={{ color: "var(--text-muted)" }}
          >
            {sessionInfoText}
          </span>
          <button
            onClick={detachSession}
            className="text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 shrink-0"
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
        className="text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 disabled:opacity-30 shrink-0"
        style={{
          color: "var(--accent-text)",
          border: "1px solid var(--accent)",
          background: "var(--accent-soft)",
        }}
        title={sessionActive ? "Switch Process" : "Attach to Process"}
      >
        <i className="fa-solid fa-crosshairs" style={{ fontSize: 10 }} />
        {sessionActive ? "Switch" : "Attach"}
      </button>

      {!isMobile && (
        <div
          className="w-px h-4 mx-1 shrink-0"
          style={{ background: "var(--border)" }}
        />
      )}

      {connected ? (
        <>
          {!isMobile && (
            <span
              className="text-xs flex items-center gap-1.5 px-2 py-0.5 rounded truncate max-w-48 shrink"
              style={{
                color: "#22c55e",
                background: "rgba(34, 197, 94, 0.08)",
              }}
            >
              <span
                className="inline-block w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: "#22c55e" }}
              />
              {serverUrl}
            </span>
          )}
          {!isMobile && deviceInfo && <DeviceBadges info={deviceInfo} />}
          <button
            onClick={disconnect}
            disabled={busy}
            className={`text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 shrink-0 ${busy ? "loading" : ""}`}
            style={{
              color: "#ef4444",
              border: "1px solid rgba(239, 68, 68, 0.3)",
            }}
            title="Disconnect"
          >
            <i className="fa-solid fa-plug-circle-xmark" style={{ fontSize: 9 }} />
            {!isMobile && "Disconnect"}
          </button>
        </>
      ) : (
        <button
          onClick={handleConnect}
          disabled={busy}
          className={`text-xs px-2 py-0.5 rounded font-medium flex items-center gap-1.5 shrink-0 ${busy ? "loading" : ""}`}
          style={{
            color: "white",
            background: "var(--accent)",
          }}
          title="Connect"
        >
          <i className="fa-solid fa-plug" style={{ fontSize: 9 }} />
          Connect
        </button>
      )}

      {!isMobile && (
        <>
          <div
            className="w-px h-4 mx-1 shrink-0"
            style={{ background: "var(--border)" }}
          />
          <button
            onClick={toggleTheme}
            className="titlebar-btn shrink-0"
            style={{ color: "var(--text-secondary)" }}
            title="Toggle Theme"
          >
            <i className={`fa-solid ${dark ? "fa-sun" : "fa-moon"}`} style={{ fontSize: 11 }} />
          </button>
        </>
      )}
    </div>
  );
}
