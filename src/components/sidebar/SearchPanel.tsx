import { useSearchStore, type SearchMatch, type ApiMatch, type SearchMode } from "@/stores/search.ts";
import { useSessionStore } from "@/stores/session.ts";
import { navigateToMemory, navigateToDisasm } from "@/lib/navigation.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

function ContextPreview({ bytes }: { bytes: number[] }) {
  if (bytes.length === 0) return null;
  const ascii = bytes.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")).join("");
  const hex = bytes.slice(0, 16).map((b) => b.toString(16).padStart(2, "0")).join(" ");
  return (
    <div className="mt-1">
      <div className="font-mono text-[10px] leading-4 break-all" style={{ color: "var(--text-muted)" }}>{hex}</div>
      <div className="font-mono text-[10px] leading-4 break-all" style={{ color: "var(--json-string)" }}>{ascii}</div>
    </div>
  );
}

function MemoryResultItem({ match }: { match: SearchMatch }) {
  return (
    <div
      className="px-3 py-1.5 border-b hover-row cursor-pointer"
      style={{ borderColor: "var(--border)" }}
      onClick={() => navigateToMemory(match.address)}
    >
      <div className="flex items-center gap-2">
        <span className="font-mono text-[11px]" style={{ color: "var(--accent-text)" }}>{match.address}</span>
        <button
          className="text-[9px] px-1 rounded icon-btn"
          style={{ color: "var(--text-muted)" }}
          onClick={(e) => { e.stopPropagation(); copyToClipboard(match.address); }}
          title="Copy address"
        >
          <i className="fa-solid fa-copy" style={{ fontSize: 8 }} />
        </button>
        <div className="flex-1" />
        {match.module && (
          <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-primary)", color: "var(--text-secondary)" }}>
            {match.module}
          </span>
        )}
      </div>
      <ContextPreview bytes={match.context} />
    </div>
  );
}

function ApiResultItem({ match }: { match: ApiMatch }) {
  const isFunction = match.name.includes("!") && !match.name.includes("variable");
  return (
    <div
      className="flex items-center gap-2 px-3 py-1 hover-row cursor-pointer"
      onClick={() => copyToClipboard(match.address)}
    >
      <span className="font-mono text-[10px] truncate flex-1" style={{ color: "var(--text-primary)" }} title={match.name}>
        {match.name}
      </span>
      {isFunction && (
        <button
          className="text-[9px] px-1 rounded icon-btn shrink-0"
          style={{ color: "#f59e0b" }}
          onClick={(e) => { e.stopPropagation(); navigateToDisasm(match.address); }}
          title="Disassemble"
        >
          <i className="fa-solid fa-microchip" style={{ fontSize: 8 }} />
        </button>
      )}
      <button
        className="text-[9px] px-1 rounded icon-btn shrink-0"
        style={{ color: "var(--accent-text)" }}
        onClick={(e) => { e.stopPropagation(); navigateToMemory(match.address); }}
        title="View in Hex"
      >
        <i className="fa-solid fa-memory" style={{ fontSize: 8 }} />
      </button>
      <span className="font-mono text-[9px] shrink-0" style={{ color: "var(--text-muted)" }}>{match.address}</span>
    </div>
  );
}

const MODE_INFO: Record<SearchMode, { label: string; placeholder: string; hint?: string }> = {
  string: { label: "String", placeholder: "Search for strings..." },
  hex: { label: "Hex", placeholder: "Hex pattern: 48 65 6c 6c 6f", hint: "Supports wildcards: 48 65 ?? 6c 6f" },
  api: { label: "API", placeholder: "exports:*!*recv*", hint: "Pattern: exports:libname!funcname (* wildcards)" },
};

export default function SearchPanel() {
  const state = useSearchStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);

  if (!sessionActive) {
    return (
      <div className="flex-1 flex items-center justify-center text-xs" style={{ color: "var(--text-muted)" }}>
        Attach to a process to search memory
      </div>
    );
  }

  const mode = MODE_INFO[state.searchMode];

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-1.5 px-3 py-2 border-b shrink-0" style={{ borderColor: "var(--border)" }}>
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>Search</span>
        {(state.results.length > 0 || state.apiResults.length > 0) && (
          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            ({state.searchMode === "api" ? state.apiResults.length : state.results.length}{state.results.length >= 500 || state.apiResults.length >= 500 ? "+" : ""})
          </span>
        )}
      </div>

      <div className="px-3 py-2 border-b shrink-0" style={{ borderColor: "var(--border)" }}>
        <div className="flex gap-0.5 mb-1.5">
          {(["string", "hex", "api"] as const).map((m) => (
            <button
              key={m}
              onClick={() => state.setSearchMode(m)}
              className="text-[10px] px-2 py-0.5 rounded icon-btn"
              style={{
                background: state.searchMode === m ? "var(--accent)" : "transparent",
                color: state.searchMode === m ? "white" : "var(--text-muted)",
              }}
            >
              {MODE_INFO[m].label}
            </button>
          ))}
        </div>
        <div className="flex gap-1">
          <input
            type="text"
            value={state.query}
            onChange={(e) => state.setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") state.search(); }}
            placeholder={mode.placeholder}
            className="text-[11px] font-mono px-2 py-1 rounded border outline-none flex-1 min-w-0"
            style={{ background: "var(--bg-input)", borderColor: "var(--border)", color: "var(--text-primary)" }}
          />
          <button
            onClick={() => state.search()}
            disabled={!state.query.trim() || state.loading}
            className={`text-[10px] px-2 py-1 rounded font-medium text-white disabled:opacity-40 ${state.loading ? "loading" : ""}`}
            style={{ background: "var(--accent)" }}
          >
            {state.loading ? "..." : "Search"}
          </button>
        </div>
        {mode.hint && (
          <div className="text-[9px] mt-1" style={{ color: "var(--text-muted)" }}>{mode.hint}</div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {state.error && (
          <div className="text-xs px-3 py-3 text-center" style={{ color: "#ef4444" }}>{state.error}</div>
        )}

        {state.loading && (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            {state.searchMode === "api" ? "Resolving APIs..." : "Scanning memory ranges..."}
          </div>
        )}

        {!state.loading && state.searchMode !== "api" && state.results.length > 0 && (
          <>
            {state.results.map((match, i) => <MemoryResultItem key={`${match.address}-${i}`} match={match} />)}
            {state.results.length >= 500 && (
              <div className="text-[10px] px-3 py-2 text-center" style={{ color: "var(--text-muted)" }}>
                Limited to 500 results. Refine your search.
              </div>
            )}
          </>
        )}

        {!state.loading && state.searchMode === "api" && state.apiResults.length > 0 && (
          <>
            {state.apiResults.map((match, i) => <ApiResultItem key={`${match.address}-${i}`} match={match} />)}
            {state.apiResults.length >= 500 && (
              <div className="text-[10px] px-3 py-2 text-center" style={{ color: "var(--text-muted)" }}>
                Limited to 500 results. Refine your pattern.
              </div>
            )}
          </>
        )}

        {!state.loading && state.searched && state.results.length === 0 && state.apiResults.length === 0 && !state.error && (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>No matches found</div>
        )}

        {!state.searched && !state.loading && (
          <div className="flex-1 flex items-center justify-center px-6 py-8">
            <div className="text-center" style={{ color: "var(--text-muted)" }}>
              <i className="fa-solid fa-magnifying-glass text-2xl mb-3 block" style={{ opacity: 0.3 }} />
              <p className="text-xs mb-2">Search across all readable memory or resolve APIs by pattern.</p>
              <p className="text-[10px] mb-1"><b>String:</b> Find text strings in memory</p>
              <p className="text-[10px] mb-1"><b>Hex:</b> Search for byte patterns with <code className="font-mono">??</code> wildcards</p>
              <p className="text-[10px]"><b>API:</b> Find functions like <code className="font-mono">exports:*!*open*</code></p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
