import { useEffect, useMemo } from "react";
import {
  useModulesStore,
  getFilteredModules,
  type ModuleTab,
  type ExportInfo,
  type ImportInfo,
  type SymbolInfo,
  type RangeInfo,
} from "@/stores/modules.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useInterceptorStore } from "@/stores/interceptor.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";
import { navigateToMemory, navigateToDisasm } from "@/lib/navigation.ts";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const TABS: Array<{ id: ModuleTab; label: string }> = [
  { id: "exports", label: "Exports" },
  { id: "imports", label: "Imports" },
  { id: "symbols", label: "Symbols" },
  { id: "sections", label: "Sections" },
];

function AddressCell({ address, className }: { address: string; className?: string }) {
  return (
    <span
      className={`font-mono shrink-0 cursor-pointer ${className ?? ""}`}
      style={{ color: "var(--text-muted)" }}
      onClick={(e) => {
        e.stopPropagation();
        copyToClipboard(address);
      }}
      title="Click to copy address"
    >
      {address}
    </span>
  );
}

function MemoryJumpBtn({ address }: { address: string }) {
  return (
    <button
      className="text-[9px] px-1 shrink-0 icon-btn"
      style={{ color: "var(--accent-text)" }}
      onClick={(e) => {
        e.stopPropagation();
        navigateToMemory(address);
      }}
      title="View in Memory"
    >
      <i className="fa-solid fa-arrow-right-to-bracket" style={{ fontSize: 8 }} />
    </button>
  );
}

function DisasmBtn({ address }: { address: string }) {
  return (
    <button
      className="text-[9px] px-1 shrink-0 icon-btn"
      style={{ color: "#f59e0b" }}
      onClick={(e) => {
        e.stopPropagation();
        navigateToDisasm(address);
      }}
      title="Disassemble"
    >
      <i className="fa-solid fa-microchip" style={{ fontSize: 8 }} />
    </button>
  );
}

function TypeBadge({ type }: { type: string }) {
  return (
    <span
      className="text-[9px] font-mono px-1 py-px rounded shrink-0"
      style={{ background: "var(--accent-soft)", color: "var(--accent-text)" }}
    >
      {type}
    </span>
  );
}

function HookBtn({ moduleName, exportName, address }: { moduleName: string; exportName: string; address: string }) {
  return (
    <button
      className="text-[9px] px-1 shrink-0 icon-btn"
      style={{ color: "#a855f7" }}
      onClick={(e) => {
        e.stopPropagation();
        useInterceptorStore.getState().quickHook(moduleName, exportName, address);
      }}
      title="Quick hook"
    >
      <i className="fa-solid fa-anchor" style={{ fontSize: 8 }} />
    </button>
  );
}

function ExportsView({ items, filter, moduleName }: { items: ExportInfo[]; filter: string; moduleName: string }) {
  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    return q ? items.filter((e) => e.name.toLowerCase().includes(q)) : items;
  }, [items, filter]);

  return (
    <>
      {filtered.map((exp, i) => (
        <div key={i} className="flex items-center gap-2 px-3 pl-8 py-0.5 text-[11px] hover-row">
          <TypeBadge type={exp.type} />
          <span className="flex-1 truncate" style={{ color: "var(--text-primary)" }}>{exp.name}</span>
          {exp.type === "function" && <HookBtn moduleName={moduleName} exportName={exp.name} address={exp.address} />}
          {exp.type === "function" && <DisasmBtn address={exp.address} />}
          <MemoryJumpBtn address={exp.address} />
          <AddressCell address={exp.address} />
        </div>
      ))}
      {filtered.length === 0 && <EmptyMessage text={filter ? "No matching exports" : "No exports"} />}
    </>
  );
}

function ImportsView({ items, filter }: { items: ImportInfo[]; filter: string }) {
  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    return q ? items.filter((e) => e.name.toLowerCase().includes(q) || e.module.toLowerCase().includes(q)) : items;
  }, [items, filter]);

  return (
    <>
      {filtered.map((imp, i) => (
        <div key={i} className="flex items-center gap-2 px-3 pl-8 py-0.5 text-[11px] hover-row">
          <TypeBadge type={imp.type || "func"} />
          <span className="flex-1 truncate" style={{ color: "var(--text-primary)" }}>{imp.name}</span>
          {imp.module && (
            <span className="text-[9px] truncate max-w-20 shrink-0" style={{ color: "var(--text-muted)" }}>
              {imp.module}
            </span>
          )}
          <MemoryJumpBtn address={imp.address} />
          <AddressCell address={imp.address} />
        </div>
      ))}
      {filtered.length === 0 && <EmptyMessage text={filter ? "No matching imports" : "No imports"} />}
    </>
  );
}

function SymbolsView({ items, filter }: { items: SymbolInfo[]; filter: string }) {
  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    return q ? items.filter((s) => s.name.toLowerCase().includes(q)) : items;
  }, [items, filter]);

  return (
    <>
      {filtered.map((sym, i) => (
        <div key={i} className="flex items-center gap-2 px-3 pl-8 py-0.5 text-[11px] hover-row">
          <TypeBadge type={sym.type} />
          {sym.isGlobal && (
            <span className="text-[8px] font-bold" style={{ color: "var(--console-ok)" }}>G</span>
          )}
          <span className="flex-1 truncate" style={{ color: "var(--text-primary)" }}>{sym.name}</span>
          {sym.type === "function" && <DisasmBtn address={sym.address} />}
          <MemoryJumpBtn address={sym.address} />
          <AddressCell address={sym.address} />
        </div>
      ))}
      {filtered.length === 0 && <EmptyMessage text={filter ? "No matching symbols" : "No symbols"} />}
    </>
  );
}

function SectionsView({ items, filter }: { items: RangeInfo[]; filter: string }) {
  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    return q ? items.filter((r) => r.protection.toLowerCase().includes(q) || r.base.toLowerCase().includes(q)) : items;
  }, [items, filter]);

  return (
    <>
      {filtered.map((range, i) => (
        <div key={i} className="flex items-center gap-2 px-3 pl-8 py-0.5 text-[11px] hover-row">
          <span
            className="text-[9px] font-mono px-1 py-px rounded shrink-0"
            style={{
              background: range.protection.includes("x") ? "rgba(239, 68, 68, 0.1)" : "var(--badge-bg)",
              color: range.protection.includes("x") ? "#ef4444" : "var(--text-secondary)",
            }}
          >
            {range.protection}
          </span>
          <span className="flex-1 truncate font-mono" style={{ color: "var(--text-primary)" }}>
            {range.base}
          </span>
          <span className="text-[10px] shrink-0" style={{ color: "var(--text-muted)" }}>
            {formatSize(range.size)}
          </span>
          <MemoryJumpBtn address={range.base} />
        </div>
      ))}
      {filtered.length === 0 && <EmptyMessage text={filter ? "No matching sections" : "No sections"} />}
    </>
  );
}

function EmptyMessage({ text }: { text: string }) {
  return (
    <div className="text-[10px] px-3 pl-8 py-1" style={{ color: "var(--text-muted)" }}>
      {text}
    </div>
  );
}

function ModuleDetail({ moduleKey, moduleName }: { moduleKey: string; moduleName: string }) {
  const state = useModulesStore();
  const { moduleTab, loadingDetail, detailFilter, exports, imports, symbols, ranges } = state;

  function getCacheForTab(key: string) {
    switch (moduleTab) {
      case "exports": return exports[key];
      case "imports": return imports[key];
      case "symbols": return symbols[key];
      case "sections": return ranges[key];
    }
  }

  const content = (() => {
    if (loadingDetail && !getCacheForTab(moduleKey)) {
      return <EmptyMessage text={`Loading ${moduleTab}...`} />;
    }
    switch (moduleTab) {
      case "exports": return <ExportsView items={exports[moduleKey] ?? []} filter={detailFilter} moduleName={moduleName} />;
      case "imports": return <ImportsView items={imports[moduleKey] ?? []} filter={detailFilter} />;
      case "symbols": return <SymbolsView items={symbols[moduleKey] ?? []} filter={detailFilter} />;
      case "sections": return <SectionsView items={ranges[moduleKey] ?? []} filter={detailFilter} />;
    }
  })();

  const count = (() => {
    const cache = getCacheForTab(moduleKey);
    return cache ? cache.length : 0;
  })();

  return (
    <div>
      <div className="flex items-center gap-1 px-3 pl-8 py-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => state.setModuleTab(tab.id)}
            className="text-[9px] px-1.5 py-0.5 rounded icon-btn"
            style={{
              background: moduleTab === tab.id ? "var(--accent)" : "transparent",
              color: moduleTab === tab.id ? "white" : "var(--text-muted)",
            }}
          >
            {tab.label}
          </button>
        ))}
        {count > 0 && (
          <span className="text-[9px] ml-0.5" style={{ color: "var(--text-muted)" }}>
            ({count})
          </span>
        )}
      </div>

      {count > 10 && (
        <div className="px-3 pl-8 pb-1">
          <input
            type="text"
            value={detailFilter}
            onChange={(e) => state.setDetailFilter(e.target.value)}
            placeholder={`Filter ${moduleTab}...`}
            className="text-[10px] px-1.5 py-0.5 rounded border outline-none w-full"
            style={{
              background: "var(--bg-input)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
          />
        </div>
      )}

      {content}
    </div>
  );
}

export default function ModuleBrowser() {
  const state = useModulesStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const filtered = getFilteredModules(state);

  useEffect(() => {
    if (sessionActive && state.modules.length === 0 && !state.loading) {
      state.enumerate();
    }
  }, [sessionActive]);

  if (!sessionActive) {
    return (
      <div
        className="flex-1 flex items-center justify-center text-xs"
        style={{ color: "var(--text-muted)" }}
      >
        Attach to a process to browse modules
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-1.5 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
          Modules
        </span>
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
          ({state.modules.length})
        </span>
        <div className="flex-1" />
        <button
          onClick={() => state.enumerate()}
          disabled={state.loading}
          className={`text-[10px] px-1.5 py-0.5 rounded border icon-btn ${state.loading ? "loading" : ""}`}
          style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
        >
          Refresh
        </button>
      </div>

      <div className="px-3 py-1.5 shrink-0">
        <input
          type="text"
          value={state.search}
          onChange={(e) => state.setSearch(e.target.value)}
          placeholder="Filter modules..."
          className="text-[11px] px-2 py-1 rounded border outline-none w-full"
          style={{
            background: "var(--bg-input)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
          }}
        />
      </div>

      <div className="flex-1 overflow-y-auto">
        {state.loading && state.modules.length === 0 ? (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            Loading modules...
          </div>
        ) : (
          filtered.map((mod) => (
            <div key={mod.base}>
              <div
                className="flex items-center gap-2 px-3 py-1 text-xs cursor-pointer hover-row group"
                onClick={() => state.toggleModule(mod.name, mod.base)}
              >
                <i
                  className={`fa-solid fa-chevron-right text-[8px] transition-transform ${state.expandedModule === mod.base ? "rotate-90" : ""}`}
                  style={{ color: "var(--text-muted)" }}
                />
                <span className="flex-1 truncate font-medium" style={{ color: "var(--text-primary)" }}>
                  {mod.name}
                </span>
                <button
                  className="text-[9px] px-1 shrink-0 opacity-0 group-hover:opacity-60 hover:!opacity-100"
                  style={{ color: "var(--text-secondary)" }}
                  onClick={(e) => {
                    e.stopPropagation();
                    state.dumpModule(mod.name);
                  }}
                  title="Download module binary"
                >
                  <i className="fa-solid fa-download" style={{ fontSize: 9 }} />
                </button>
                <button
                  className="text-[9px] px-1 shrink-0 opacity-0 group-hover:opacity-60 hover:!opacity-100"
                  style={{ color: "var(--text-secondary)" }}
                  onClick={(e) => {
                    e.stopPropagation();
                    copyToClipboard(mod.base);
                  }}
                  title="Copy base address"
                >
                  <i className="fa-solid fa-copy" style={{ fontSize: 9 }} />
                </button>
                <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
                  {mod.base}
                </span>
                <span className="text-[10px] shrink-0" style={{ color: "var(--text-muted)" }}>
                  {formatSize(mod.size)}
                </span>
              </div>
              {state.expandedModule === mod.base && <ModuleDetail moduleKey={mod.base} moduleName={mod.name} />}
            </div>
          ))
        )}
        {!state.loading && filtered.length === 0 && state.modules.length > 0 && (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            No matching modules
          </div>
        )}
      </div>

      {state.dumping && (
        <div
          className="flex items-center gap-2 px-3 py-1.5 border-t shrink-0"
          style={{ borderColor: "var(--border)" }}
        >
          <div className="loading w-3 h-3" />
          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            Dumping module...
          </span>
        </div>
      )}
    </div>
  );
}
