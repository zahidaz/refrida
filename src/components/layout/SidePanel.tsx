import { useLayoutStore } from "@/stores/layout.ts";
import ScriptLibrary from "@/components/sidebar/ScriptLibrary.tsx";
import SettingsPanel from "@/components/sidebar/SettingsPanel.tsx";

interface Props {
  onLoadScript: (name: string, content: string) => void;
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
      {activeActivity === "settings" && <SettingsPanel />}
    </div>
  );
}
