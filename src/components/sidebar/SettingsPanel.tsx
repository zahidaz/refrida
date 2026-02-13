import { useThemeStore } from "@/stores/theme.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useConnectionStore } from "@/stores/connection.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import { getItem, setItem } from "@/lib/storage.ts";

const HISTORY_KEY = "refrida-connection-history";

export interface HistoryEntry {
  host: string;
  tls: string;
  date: string;
}

export function getConnectionHistory(): HistoryEntry[] {
  return getItem<HistoryEntry[]>(HISTORY_KEY, []);
}

export function addToHistory(host: string, tls: string) {
  const history = getConnectionHistory().filter((h) => h.host !== host);
  history.unshift({ host, tls, date: new Date().toISOString() });
  setItem(HISTORY_KEY, history.slice(0, 10));
}

export function removeFromHistory(host: string) {
  const history = getConnectionHistory().filter((h) => h.host !== host);
  setItem(HISTORY_KEY, history);
}

export default function SettingsPanel() {
  const { dark, toggle: toggleTheme } = useThemeStore();
  const { scriptRuntime, setScriptRuntime } = useSessionStore();
  const { setServerUrl, setTls } = useConnectionStore();
  const { setConnectionDialogOpen } = useLayoutStore();
  const history = getConnectionHistory();

  function connectTo(entry: HistoryEntry) {
    setServerUrl(entry.host);
    setTls(entry.tls);
    setConnectionDialogOpen(true);
  }

  function handleRemove(e: React.MouseEvent, host: string) {
    e.stopPropagation();
    removeFromHistory(host);
  }

  return (
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
      <div className="flex-1 overflow-y-auto px-3 py-3 flex flex-col gap-4">
        <Section title="Connection History">
          {history.length === 0 ? (
            <p className="text-[11px]" style={{ color: "var(--text-muted)" }}>
              No recent connections.
            </p>
          ) : (
            <div className="flex flex-col gap-1">
              {history.map((entry) => (
                <div
                  key={entry.host}
                  className="hover-row flex items-center justify-between px-2 py-1 rounded cursor-pointer group"
                  onClick={() => connectTo(entry)}
                >
                  <div>
                    <p
                      className="text-xs"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {entry.host}
                    </p>
                    <p
                      className="text-[10px]"
                      style={{ color: "var(--text-muted)" }}
                    >
                      TLS: {entry.tls}
                    </p>
                  </div>
                  <button
                    onClick={(e) => handleRemove(e, entry.host)}
                    className="text-[10px] opacity-0 group-hover:opacity-60 hover:!opacity-100 px-1"
                    style={{ color: "var(--text-muted)" }}
                    title="Remove"
                  >
                    <i className="fa-solid fa-xmark" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </Section>

        <Section title="Script Runtime">
          <div className="flex flex-col gap-1">
            {(["default", "qjs", "v8"] as const).map((rt) => (
              <label
                key={rt}
                className="flex items-center gap-2 px-2 py-1 rounded cursor-pointer hover-row"
              >
                <input
                  type="radio"
                  name="runtime"
                  checked={scriptRuntime === rt}
                  onChange={() => setScriptRuntime(rt)}
                  className="accent-[var(--accent)]"
                />
                <span
                  className="text-xs"
                  style={{ color: "var(--text-primary)" }}
                >
                  {rt === "default" ? "Default" : rt.toUpperCase()}
                </span>
              </label>
            ))}
          </div>
        </Section>

        <Section title="Appearance">
          <div className="flex flex-col gap-1">
            <label className="flex items-center gap-2 px-2 py-1 rounded cursor-pointer hover-row">
              <input
                type="radio"
                name="theme"
                checked={!dark}
                onChange={() => { if (dark) toggleTheme(); }}
                className="accent-[var(--accent)]"
              />
              <span
                className="text-xs"
                style={{ color: "var(--text-primary)" }}
              >
                Light
              </span>
            </label>
            <label className="flex items-center gap-2 px-2 py-1 rounded cursor-pointer hover-row">
              <input
                type="radio"
                name="theme"
                checked={dark}
                onChange={() => { if (!dark) toggleTheme(); }}
                className="accent-[var(--accent)]"
              />
              <span
                className="text-xs"
                style={{ color: "var(--text-primary)" }}
              >
                Dark
              </span>
            </label>
          </div>
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p
        className="text-[10px] font-semibold uppercase tracking-wide mb-1.5"
        style={{ color: "var(--text-muted)" }}
      >
        {title}
      </p>
      {children}
    </div>
  );
}
