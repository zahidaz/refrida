import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import {
  enumerateModulesScript,
  enumerateExportsScript,
  enumerateImportsScript,
  enumerateSymbolsScript,
  enumerateRangesScript,
  dumpModuleScript,
} from "@/lib/utilityScripts.ts";

export interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  path: string;
}

export interface ExportInfo {
  type: string;
  name: string;
  address: string;
}

export interface ImportInfo {
  type: string;
  name: string;
  module: string;
  address: string;
}

export interface SymbolInfo {
  name: string;
  address: string;
  type: string;
  isGlobal: boolean;
}

export interface RangeInfo {
  base: string;
  size: number;
  protection: string;
}

export type ModuleTab = "exports" | "imports" | "symbols" | "sections";

interface DumpChunk {
  offset: number;
  bytes: number[];
  error?: string;
}

interface ModulesState {
  modules: ModuleInfo[];
  expandedModule: string | null;
  expandedModuleName: string | null;
  moduleTab: ModuleTab;
  detailFilter: string;
  exports: Record<string, ExportInfo[]>;
  imports: Record<string, ImportInfo[]>;
  symbols: Record<string, SymbolInfo[]>;
  ranges: Record<string, RangeInfo[]>;
  search: string;
  loading: boolean;
  loadingDetail: boolean;
  dumping: boolean;
  enumerate: () => Promise<void>;
  fetchDetail: (key: string, moduleName: string, tab: ModuleTab) => Promise<void>;
  toggleModule: (name: string, base: string) => void;
  setModuleTab: (tab: ModuleTab) => void;
  setSearch: (q: string) => void;
  setDetailFilter: (q: string) => void;
  dumpModule: (moduleName: string) => Promise<void>;
  reset: () => void;
}

function getCacheForTab(state: ModulesState, tab: ModuleTab, name: string): unknown[] | undefined {
  switch (tab) {
    case "exports": return state.exports[name];
    case "imports": return state.imports[name];
    case "symbols": return state.symbols[name];
    case "sections": return state.ranges[name];
  }
}

export const useModulesStore = create<ModulesState>((set, get) => ({
  modules: [],
  expandedModule: null,
  expandedModuleName: null,
  moduleTab: "exports",
  detailFilter: "",
  exports: {},
  imports: {},
  symbols: {},
  ranges: {},
  search: "",
  loading: false,
  loadingDetail: false,
  dumping: false,

  enumerate: async () => {
    set({ loading: true });
    const result = await runUtilityScript<ModuleInfo>(enumerateModulesScript());
    set({ modules: result.data, loading: false, expandedModule: null, expandedModuleName: null });
  },

  fetchDetail: async (key: string, moduleName: string, tab: ModuleTab) => {
    set({ loadingDetail: true });
    switch (tab) {
      case "exports": {
        const r = await runUtilityScript<ExportInfo>(enumerateExportsScript(moduleName));
        set((s) => ({ exports: { ...s.exports, [key]: r.data }, loadingDetail: false }));
        break;
      }
      case "imports": {
        const r = await runUtilityScript<ImportInfo>(enumerateImportsScript(moduleName));
        set((s) => ({ imports: { ...s.imports, [key]: r.data }, loadingDetail: false }));
        break;
      }
      case "symbols": {
        const r = await runUtilityScript<SymbolInfo>(enumerateSymbolsScript(moduleName));
        set((s) => ({ symbols: { ...s.symbols, [key]: r.data }, loadingDetail: false }));
        break;
      }
      case "sections": {
        const r = await runUtilityScript<RangeInfo>(enumerateRangesScript(moduleName));
        set((s) => ({ ranges: { ...s.ranges, [key]: r.data }, loadingDetail: false }));
        break;
      }
    }
  },

  toggleModule: (name: string, base: string) => {
    const { expandedModule, moduleTab, fetchDetail } = get();
    if (expandedModule === base) {
      set({ expandedModule: null, expandedModuleName: null, detailFilter: "" });
    } else {
      set({ expandedModule: base, expandedModuleName: name, detailFilter: "" });
      if (!getCacheForTab(get(), moduleTab, base)) {
        fetchDetail(base, name, moduleTab);
      }
    }
  },

  setModuleTab: (tab: ModuleTab) => {
    const { expandedModule, expandedModuleName, fetchDetail } = get();
    set({ moduleTab: tab, detailFilter: "" });
    if (expandedModule && expandedModuleName && !getCacheForTab(get(), tab, expandedModule)) {
      fetchDetail(expandedModule, expandedModuleName, tab);
    }
  },

  setSearch: (search) => set({ search }),
  setDetailFilter: (detailFilter) => set({ detailFilter }),

  dumpModule: async (moduleName: string) => {
    set({ dumping: true });
    const result = await runUtilityScript<DumpChunk>(dumpModuleScript(moduleName));
    set({ dumping: false });
    if (result.data.length === 0) return;

    const mod = get().modules.find((m) => m.name === moduleName);
    const totalSize = mod?.size ?? result.data.reduce((s, c) => s + c.bytes.length, 0);
    const buffer = new Uint8Array(totalSize);
    for (const chunk of result.data) {
      buffer.set(chunk.bytes, chunk.offset);
    }
    const blob = new Blob([buffer], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = moduleName;
    a.click();
    URL.revokeObjectURL(url);
  },

  reset: () =>
    set({
      modules: [],
      expandedModule: null,
      expandedModuleName: null,
      moduleTab: "exports",
      detailFilter: "",
      exports: {},
      imports: {},
      symbols: {},
      ranges: {},
      search: "",
      loading: false,
      loadingDetail: false,
      dumping: false,
    }),
}));

export function getFilteredModules(state: ModulesState): ModuleInfo[] {
  const q = state.search.toLowerCase().trim();
  if (!q) return state.modules;
  return state.modules.filter(
    (m) => m.name.toLowerCase().includes(q) || m.path.toLowerCase().includes(q),
  );
}
