import { useConsoleStore, getRunIds, type LogLevel } from "@/stores/console.ts";
import { useLayoutStore } from "@/stores/layout.ts";

const FILTERS: Array<{ label: string; value: LogLevel | "all" }> = [
  { label: "All", value: "all" },
  { label: "Info", value: "info" },
  { label: "Warn", value: "warning" },
  { label: "Error", value: "error" },
  { label: "System", value: "system" },
];

export default function ConsoleToolbar() {
  const state = useConsoleStore();
  const {
    search,
    setSearch,
    filter,
    setFilter,
    filterRunId,
    setFilterRunId,
    exportFormat,
    setExportFormat,
    exportConsole,
    clear,
    lines,
  } = state;
  const setBottomPanelVisible = useLayoutStore(
    (s) => s.setBottomPanelVisible,
  );

  const runIds = getRunIds(state);

  return (
    <div
      className="flex items-center gap-1.5 px-2 py-1 border-b"
      style={{
        borderColor: "var(--border)",
        background: "var(--bg-secondary)",
      }}
    >
      <span
        className="text-xs font-semibold"
        style={{ color: "var(--text-primary)" }}
      >
        Console
      </span>
      <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
        ({lines.length})
      </span>

      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search..."
        className="text-[11px] px-1.5 py-0.5 rounded border outline-none w-28"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      />

      {FILTERS.map((f) => (
        <button
          key={f.value}
          onClick={() => setFilter(f.value)}
          className={`console-filter-btn ${filter === f.value ? "active" : ""}`}
        >
          {f.label}
        </button>
      ))}

      {runIds.length > 1 && (
        <select
          value={filterRunId === null ? "all" : String(filterRunId)}
          onChange={(e) =>
            setFilterRunId(e.target.value === "all" ? null : Number(e.target.value))
          }
          className="text-[11px] px-1 py-0.5 rounded border outline-none"
          style={{
            background: "var(--bg-input)",
            borderColor: filterRunId !== null ? "var(--accent)" : "var(--border)",
            color: filterRunId !== null ? "var(--accent-text)" : "var(--text-primary)",
          }}
        >
          <option value="all">All Runs</option>
          {runIds.map((id) => (
            <option key={id} value={String(id)}>
              Run #{id}
            </option>
          ))}
        </select>
      )}

      <div className="flex-1" />

      <select
        value={exportFormat}
        onChange={(e) =>
          setExportFormat(e.target.value as "txt" | "json" | "csv")
        }
        className="text-[11px] px-1 py-0.5 rounded border outline-none"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      >
        <option value="txt">.txt</option>
        <option value="json">.json</option>
        <option value="csv">.csv</option>
      </select>

      <button
        onClick={exportConsole}
        disabled={lines.length === 0}
        className="text-[11px] px-1.5 py-0.5 rounded border disabled:opacity-40"
        style={{
          borderColor: "var(--border)",
          color: "var(--text-secondary)",
        }}
      >
        Export
      </button>

      <button
        onClick={clear}
        className="text-[11px] px-1.5 py-0.5 rounded border"
        style={{
          borderColor: "var(--border)",
          color: "var(--text-secondary)",
        }}
        title="Clear (Ctrl+Shift+K)"
      >
        Clear
      </button>

      <button
        onClick={() => setBottomPanelVisible(false)}
        className="text-sm px-1 ml-1"
        style={{ color: "var(--text-muted)" }}
        title="Close Console"
      >
        <i className="fa-solid fa-xmark" />
      </button>
    </div>
  );
}
