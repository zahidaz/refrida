import { useLayoutStore, type Activity } from "@/stores/layout.ts";
import { useCrashesStore } from "@/stores/crashes.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";

const ACTIVITIES: Array<{ id: Activity; icon: string; label: string }> = [
  { id: "scripts", icon: "fa-code", label: "Scripts" },
  { id: "modules", icon: "fa-cubes", label: "Modules" },
  { id: "memory", icon: "fa-memory", label: "Memory" },
  { id: "search", icon: "fa-magnifying-glass", label: "Search" },
  { id: "stalker", icon: "fa-route", label: "Stalker" },
  { id: "interceptor", icon: "fa-anchor", label: "Interceptor" },
  { id: "bookmarks", icon: "fa-bookmark", label: "Bookmarks" },
  { id: "monitors", icon: "fa-wave-square", label: "Monitors" },
  { id: "crashes", icon: "fa-bug", label: "Crashes" },
  { id: "settings", icon: "fa-gear", label: "Settings" },
];

export default function ActivityBar() {
  const { activeActivity, sidePanelVisible, toggleActivity } = useLayoutStore();
  const hasNewCrash = useCrashesStore((s) => s.hasNew);
  const isMobile = useIsMobile();

  if (isMobile) {
    return (
      <div className="mobile-bottom-nav">
        {ACTIVITIES.map((a) => (
          <button
            key={a.id}
            onClick={() => toggleActivity(a.id)}
            style={{
              color:
                activeActivity === a.id && sidePanelVisible
                  ? "var(--accent-text)"
                  : "var(--text-muted)",
              background:
                activeActivity === a.id && sidePanelVisible
                  ? "var(--accent-soft)"
                  : "transparent",
            }}
            title={a.label}
          >
            <i className={`fa-solid ${a.icon}`} style={{ fontSize: 16 }} />
          </button>
        ))}
      </div>
    );
  }

  return (
    <div
      className="flex flex-col items-center py-1 border-r"
      style={{
        width: 40,
        minWidth: 40,
        background: "var(--bg-secondary)",
        borderColor: "var(--border)",
      }}
    >
      {ACTIVITIES.map((a) => (
        <button
          key={a.id}
          onClick={() => toggleActivity(a.id)}
          className="relative flex items-center justify-center w-8 h-8 rounded cursor-pointer mb-0.5"
          style={{
            color:
              activeActivity === a.id && sidePanelVisible
                ? "var(--accent-text)"
                : "var(--text-muted)",
            background:
              activeActivity === a.id && sidePanelVisible
                ? "var(--accent-soft)"
                : "transparent",
          }}
          title={a.label}
        >
          <i className={`fa-solid ${a.icon} text-sm`} />
          {a.id === "crashes" && hasNewCrash && (
            <span
              className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full"
              style={{ background: "#ef4444" }}
            />
          )}
        </button>
      ))}
    </div>
  );
}
