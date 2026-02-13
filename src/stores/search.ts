import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { searchMemoryScript } from "@/lib/utilityScripts.ts";

export interface SearchMatch {
  address: string;
  size: number;
  context: number[];
  module: string | null;
}

interface SearchState {
  query: string;
  searchType: "string" | "hex";
  results: SearchMatch[];
  loading: boolean;
  error: string | null;
  searched: boolean;
  setQuery: (q: string) => void;
  setSearchType: (t: "string" | "hex") => void;
  search: () => Promise<void>;
  reset: () => void;
}

export const useSearchStore = create<SearchState>((set, get) => ({
  query: "",
  searchType: "string",
  results: [],
  loading: false,
  error: null,
  searched: false,

  setQuery: (query) => set({ query }),
  setSearchType: (searchType) => set({ searchType }),

  search: async () => {
    const { query, searchType } = get();
    if (!query.trim()) return;
    set({ loading: true, error: null, results: [], searched: true });
    const isHex = searchType === "hex";
    const result = await runUtilityScript<SearchMatch>(
      searchMemoryScript(query, isHex),
    );
    if (result.error) {
      set({ loading: false, error: result.error });
    } else {
      set({ loading: false, results: result.data });
    }
  },

  reset: () => set({ query: "", results: [], loading: false, error: null, searched: false }),
}));
