import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { searchMemoryScript, apiResolverScript } from "@/lib/utilityScripts.ts";

export interface SearchMatch {
  address: string;
  size: number;
  context: number[];
  module: string | null;
}

export interface ApiMatch {
  name: string;
  address: string;
  module: string | null;
}

export type SearchMode = "string" | "hex" | "api";

interface SearchState {
  query: string;
  searchMode: SearchMode;
  results: SearchMatch[];
  apiResults: ApiMatch[];
  loading: boolean;
  error: string | null;
  searched: boolean;
  setQuery: (q: string) => void;
  setSearchMode: (m: SearchMode) => void;
  search: () => Promise<void>;
  reset: () => void;
}

export const useSearchStore = create<SearchState>((set, get) => ({
  query: "",
  searchMode: "string",
  results: [],
  apiResults: [],
  loading: false,
  error: null,
  searched: false,

  setQuery: (query) => set({ query }),
  setSearchMode: (searchMode) => set({ searchMode }),

  search: async () => {
    const { query, searchMode } = get();
    if (!query.trim()) return;
    set({ loading: true, error: null, results: [], apiResults: [], searched: true });

    if (searchMode === "api") {
      const result = await runUtilityScript<ApiMatch | { truncated: boolean; total: number }>(
        apiResolverScript(query),
        "api-resolve",
      );
      if (result.error) {
        set({ loading: false, error: result.error });
      } else {
        const matches = result.data.filter((d): d is ApiMatch => "name" in d);
        set({ loading: false, apiResults: matches });
      }
    } else {
      const isHex = searchMode === "hex";
      const result = await runUtilityScript<SearchMatch>(
        searchMemoryScript(query, isHex),
        "memory-search",
      );
      if (result.error) {
        set({ loading: false, error: result.error });
      } else {
        set({ loading: false, results: result.data });
      }
    }
  },

  reset: () => set({ query: "", results: [], apiResults: [], loading: false, error: null, searched: false }),
}));
