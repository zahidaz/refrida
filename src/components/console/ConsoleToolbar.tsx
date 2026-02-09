import { useConsoleStore, type LogLevel } from "@/stores/console.ts";

const FILTERS: Array<{ label: string; value: LogLevel | "all" }> = [
  { label: "All", value: "all" },
  { label: "Info", value: "info" },
  { label: "Warn", value: "warning" },
  { label: "Error", value: "error" },
  { label: "System", value: "system" },
];

export default function ConsoleToolbar() {
  const {
    search,
    setSearch,
    filter,
    setFilter,
    exportFormat,
    setExportFormat,
    exportConsole,
    clear,
    lines,
  } = useConsoleStore();

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
    </div>
  );
}
