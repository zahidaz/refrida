import { describe, it, expect, beforeEach } from "vitest";
import { useSearchStore } from "@/stores/search.ts";

describe("search store", () => {
  beforeEach(() => {
    useSearchStore.setState({
      query: "",
      searchMode: "string",
      results: [],
      apiResults: [],
      loading: false,
      error: null,
      searched: false,
    });
  });

  describe("setQuery", () => {
    it("updates query", () => {
      useSearchStore.getState().setQuery("test search");
      expect(useSearchStore.getState().query).toBe("test search");
    });
  });

  describe("setSearchMode", () => {
    it("updates search mode to hex", () => {
      useSearchStore.getState().setSearchMode("hex");
      expect(useSearchStore.getState().searchMode).toBe("hex");
    });

    it("updates search mode to api", () => {
      useSearchStore.getState().setSearchMode("api");
      expect(useSearchStore.getState().searchMode).toBe("api");
    });
  });

  describe("reset", () => {
    it("clears all state", () => {
      useSearchStore.setState({
        query: "test",
        results: [{ address: "0x1000", size: 4, context: [1, 2], module: "libc.so" }],
        apiResults: [{ name: "malloc", address: "0x2000", module: "libc.so" }],
        loading: true,
        error: "test error",
        searched: true,
      });
      useSearchStore.getState().reset();
      const state = useSearchStore.getState();
      expect(state.query).toBe("");
      expect(state.results).toHaveLength(0);
      expect(state.apiResults).toHaveLength(0);
      expect(state.loading).toBe(false);
      expect(state.error).toBeNull();
      expect(state.searched).toBe(false);
    });
  });
});
