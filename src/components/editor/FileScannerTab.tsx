import { useMemo } from "react";
import { useFileScannerStore, type FileMatch } from "@/stores/fileScanner.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

const TYPE_COLORS: Record<string, string> = {
  PNG: "#22c55e",
  JPEG: "#f59e0b",
  GIF: "#a855f7",
  PDF: "#ef4444",
  ZIP: "#3b82f6",
  ELF: "#06b6d4",
  MachO: "#8b5cf6",
  PE: "#ec4899",
  SQLite: "#14b8a6",
  DEX: "#f97316",
  BPLIST: "#64748b",
  PEM: "#eab308",
  GZIP: "#6366f1",
  BZ2: "#0ea5e9",
  "7Z": "#d946ef",
  OGG: "#84cc16",
  FLAC: "#10b981",
  RIFF: "#f43f5e",
};

function TypeBadge({ type }: { type: string }) {
  const color = TYPE_COLORS[type] ?? "var(--text-muted)";
  return (
    <span
      className="text-[9px] font-medium px-1.5 py-px rounded shrink-0"
      style={{ color, background: `${color}15` }}
    >
      {type}
    </span>
  );
}

function ResultRow({ match, onOpenHex }: { match: FileMatch; onOpenHex: (addr: string) => void }) {
  const dumpFile = useFileScannerStore((s) => s.dumpFile);

  return (
    <div className="flex items-center gap-2 px-4 py-1.5 hover-row text-[11px] group">
      <TypeBadge type={match.fileType} />
      <span
        className="font-mono cursor-pointer shrink-0"
        style={{ color: "var(--accent-text)" }}
        onClick={() => copyToClipboard(match.address)}
        title="Copy address"
      >
        {match.address}
      </span>
      {match.module && (
        <span className="truncate" style={{ color: "var(--text-secondary)" }}>
          {match.module}
        </span>
      )}
      {match.offset && (
        <span className="font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>
          +{match.offset}
        </span>
      )}
      <div className="flex-1" />
      <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          className="text-[9px] px-1.5 py-0.5 rounded icon-btn"
          style={{ color: "var(--text-muted)" }}
          onClick={() => onOpenHex(match.address)}
          title="Open in Hex Viewer"
        >
          <i className="fa-solid fa-memory" style={{ fontSize: 9 }} />
        </button>
        <button
          className="text-[9px] px-1.5 py-0.5 rounded icon-btn"
          style={{ color: "var(--text-muted)" }}
          onClick={() => dumpFile(match.address, match.fileType)}
          title="Dump / Download"
        >
          <i className="fa-solid fa-download" style={{ fontSize: 9 }} />
        </button>
        <button
          className="text-[9px] px-1.5 py-0.5 rounded icon-btn"
          style={{ color: "var(--text-muted)" }}
          onClick={() => copyToClipboard(match.address)}
          title="Copy Address"
        >
          <i className="fa-solid fa-copy" style={{ fontSize: 9 }} />
        </button>
      </div>
    </div>
  );
}

export default function FileScannerTab() {
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const { results, loading, error, scanned, filterType, filterSearch, sortBy, scan, setFilterType, setFilterSearch, setSortBy } = useFileScannerStore();

  const fileTypes = useMemo(() => {
    const types = new Set<string>();
    for (const r of results) types.add(r.fileType);
    return Array.from(types).sort();
  }, [results]);

  const filtered = useMemo(() => {
    let list = results;
    if (filterType) {
      list = list.filter((r) => r.fileType === filterType);
    }
    if (filterSearch) {
      const q = filterSearch.toLowerCase();
      list = list.filter(
        (r) =>
          r.address.toLowerCase().includes(q) ||
          (r.module ?? "").toLowerCase().includes(q),
      );
    }
    if (sortBy === "type") {
      list = [...list].sort((a, b) => a.fileType.localeCompare(b.fileType));
    } else if (sortBy === "address") {
      list = [...list].sort((a, b) => a.address.localeCompare(b.address));
    } else if (sortBy === "module") {
      list = [...list].sort((a, b) => (a.module ?? "").localeCompare(b.module ?? ""));
    }
    return list;
  }, [results, filterType, filterSearch, sortBy]);

  function handleOpenHex(address: string) {
    useScriptsStore.getState().openHexTab(address, () => "");
  }

  function handleExport() {
    const json = JSON.stringify(filtered, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "file-scan-results.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  if (!sessionActive) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2">
        <i className="fa-solid fa-magnifying-glass text-2xl" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
        <span className="text-xs" style={{ color: "var(--text-muted)" }}>Attach to a process to scan files</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--bg-primary)" }}>
      <div className="flex items-center gap-2 px-4 py-2 border-b shrink-0" style={{ borderColor: "var(--border)" }}>
        <button
          onClick={scan}
          disabled={loading}
          className="flex items-center gap-1.5 text-[11px] font-medium px-3 py-1 rounded disabled:opacity-50"
          style={{ color: "white", background: loading ? "var(--text-muted)" : "var(--accent)" }}
        >
          {loading ? (
            <>
              <i className="fa-solid fa-spinner fa-spin" style={{ fontSize: 10 }} />
              Scanning...
            </>
          ) : (
            <>
              <i className="fa-solid fa-magnifying-glass" style={{ fontSize: 10 }} />
              {scanned ? "Re-scan" : "Scan Memory"}
            </>
          )}
        </button>

        {scanned && (
          <>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="text-[11px] px-2 py-1 rounded border outline-none"
              style={{ background: "var(--bg-primary)", borderColor: "var(--border)", color: "var(--text-primary)" }}
            >
              <option value="">All Types</option>
              {fileTypes.map((t) => (
                <option key={t} value={t}>{t} ({results.filter((r) => r.fileType === t).length})</option>
              ))}
            </select>

            <input
              type="text"
              value={filterSearch}
              onChange={(e) => setFilterSearch(e.target.value)}
              placeholder="Filter by address or module..."
              className="text-[11px] px-2 py-1 rounded border outline-none flex-1 max-w-[240px]"
              style={{ background: "var(--bg-primary)", borderColor: "var(--border)", color: "var(--text-primary)" }}
            />

            <div className="flex-1" />

            <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
              {filtered.length}{filterType || filterSearch ? ` / ${results.length}` : ""} results
            </span>

            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as "type" | "address" | "module")}
              className="text-[10px] px-1.5 py-0.5 rounded border outline-none"
              style={{ background: "var(--bg-primary)", borderColor: "var(--border)", color: "var(--text-muted)" }}
            >
              <option value="type">Sort: Type</option>
              <option value="address">Sort: Address</option>
              <option value="module">Sort: Module</option>
            </select>

            <button
              onClick={handleExport}
              disabled={filtered.length === 0}
              className="text-[9px] px-1.5 py-0.5 rounded icon-btn disabled:opacity-30"
              style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}
              title="Export as JSON"
            >
              <i className="fa-solid fa-file-export" style={{ fontSize: 9 }} />
            </button>
          </>
        )}
      </div>

      {error && (
        <div className="px-4 py-2 text-[11px]" style={{ color: "#ef4444" }}>{error}</div>
      )}

      <div className="flex items-center gap-3 px-4 py-1 text-[9px] font-semibold border-b shrink-0" style={{ borderColor: "var(--border)", color: "var(--text-muted)" }}>
        <span className="w-14 shrink-0">Type</span>
        <span className="w-32 shrink-0">Address</span>
        <span className="flex-1">Module</span>
        <span className="w-20 shrink-0">Offset</span>
        <span className="w-20 shrink-0 text-right">Actions</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {!scanned && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-3">
            <i className="fa-solid fa-file-zipper text-3xl" style={{ color: "var(--text-muted)", opacity: 0.2 }} />
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>Scan memory to find embedded files</span>
            <span className="text-[10px]" style={{ color: "var(--text-muted)", opacity: 0.6 }}>
              Detects PNG, JPEG, PDF, ZIP, ELF, MachO, SQLite, and more
            </span>
          </div>
        ) : loading && results.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2">
            <i className="fa-solid fa-spinner fa-spin text-lg" style={{ color: "var(--text-muted)" }} />
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>Scanning memory ranges...</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2">
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              {filterType || filterSearch ? "No matching results" : "No file signatures found"}
            </span>
          </div>
        ) : (
          filtered.map((m, i) => (
            <ResultRow key={`${m.address}-${m.fileType}-${i}`} match={m} onOpenHex={handleOpenHex} />
          ))
        )}
      </div>
    </div>
  );
}
