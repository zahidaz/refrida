import { describe, it, expect, beforeEach } from "vitest";
import { useSnippetsStore } from "@/stores/snippets.ts";

describe("snippets store", () => {
  beforeEach(() => {
    useSnippetsStore.setState({
      snippets: [],
      loading: false,
      error: null,
      fetched: false,
    });
  });

  describe("initial state", () => {
    it("starts with empty snippets", () => {
      const state = useSnippetsStore.getState();
      expect(state.snippets).toHaveLength(0);
      expect(state.loading).toBe(false);
      expect(state.fetched).toBe(false);
    });
  });

  describe("fetch guard", () => {
    it("does not refetch if already fetched", async () => {
      useSnippetsStore.setState({ fetched: true });
      await useSnippetsStore.getState().fetch();
      expect(useSnippetsStore.getState().loading).toBe(false);
    });

    it("does not refetch if already loading", async () => {
      useSnippetsStore.setState({ loading: true });
      await useSnippetsStore.getState().fetch();
      expect(useSnippetsStore.getState().fetched).toBe(false);
    });
  });
});
