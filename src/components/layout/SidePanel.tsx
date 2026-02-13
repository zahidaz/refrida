import { useLayoutStore } from "@/stores/layout.ts";
import ScriptLibrary from "@/components/sidebar/ScriptLibrary.tsx";

interface Props {
  onLoadScript: (content: string) => void;
}

export default function SidePanel({ onLoadScript }: Props) {
  const activeActivity = useLayoutStore((s) => s.activeActivity);

  return (
    <div
      className="flex flex-col h-full border-r"
      style={{
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      {activeActivity === "scripts" && (
        <ScriptLibrary onLoadScript={onLoadScript} />
      )}
      {activeActivity === "settings" && (
        <div className="flex flex-col h-full">
          <div
            className="flex items-center px-2 py-1.5 border-b"
            style={{ borderColor: "var(--border)" }}
          >
            <span
              className="text-xs font-semibold"
              style={{ color: "var(--text-primary)" }}
            >
              Settings
            </span>
          </div>
          <div
            className="text-xs px-3 py-4 text-center"
            style={{ color: "var(--text-muted)" }}
          >
            Settings will be available in a future update.
          </div>
        </div>
      )}
    </div>
  );
}
