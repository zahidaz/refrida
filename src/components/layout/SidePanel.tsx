import { useLayoutStore } from "@/stores/layout.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";
import ScriptLibrary from "@/components/sidebar/ScriptLibrary.tsx";
import SettingsPanel from "@/components/sidebar/SettingsPanel.tsx";

interface Props {
  onLoadScript: (name: string, content: string) => void;
}

export default function SidePanel({ onLoadScript }: Props) {
  const activeActivity = useLayoutStore((s) => s.activeActivity);
  const setSidePanelVisible = useLayoutStore((s) => s.setSidePanelVisible);
  const isMobile = useIsMobile();

  return (
    <div
      className="flex flex-col h-full border-r"
      style={{
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      {isMobile && (
        <div
          className="flex items-center justify-between px-3 py-2 shrink-0 border-b"
          style={{ borderColor: "var(--border)" }}
        >
          <span
            className="text-xs font-semibold"
            style={{ color: "var(--text-primary)" }}
          >
            {activeActivity === "scripts" ? "Scripts" : "Settings"}
          </span>
          <button
            onClick={() => setSidePanelVisible(false)}
            className="flex items-center justify-center w-8 h-8 rounded"
            style={{ color: "var(--text-muted)" }}
          >
            <i className="fa-solid fa-xmark" style={{ fontSize: 14 }} />
          </button>
        </div>
      )}
      {activeActivity === "scripts" && (
        <ScriptLibrary onLoadScript={onLoadScript} />
      )}
      {activeActivity === "settings" && <SettingsPanel />}
    </div>
  );
}
