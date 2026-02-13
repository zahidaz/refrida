import { describe, it, expect, beforeEach } from "vitest";
import { useFileScannerStore } from "@/stores/fileScanner.ts";

describe("fileScanner store", () => {
  beforeEach(() => {
    useFileScannerStore.setState({
      results: [],
      loading: false,
      error: null,
      filterType: "",
      filterSearch: "",
      sortBy: "type",
      scanned: false,
    });
  });

  describe("setFilterType", () => {
    it("updates filter type", () => {
      useFileScannerStore.getState().setFilterType("PNG");
      expect(useFileScannerStore.getState().filterType).toBe("PNG");
    });
  });

  describe("setFilterSearch", () => {
    it("updates filter search", () => {
      useFileScannerStore.getState().setFilterSearch("0x1000");
      expect(useFileScannerStore.getState().filterSearch).toBe("0x1000");
    });
  });

  describe("setSortBy", () => {
    it("changes sort to address", () => {
      useFileScannerStore.getState().setSortBy("address");
      expect(useFileScannerStore.getState().sortBy).toBe("address");
    });

    it("changes sort to module", () => {
      useFileScannerStore.getState().setSortBy("module");
      expect(useFileScannerStore.getState().sortBy).toBe("module");
    });
  });

  describe("reset", () => {
    it("clears all state", () => {
      useFileScannerStore.setState({
        results: [
          { address: "0x1000", fileType: "PNG", module: "lib.so", offset: "0x100" },
        ],
        loading: true,
        error: "test",
        scanned: true,
        filterType: "PNG",
        filterSearch: "test",
      });
      useFileScannerStore.getState().reset();
      const state = useFileScannerStore.getState();
      expect(state.results).toHaveLength(0);
      expect(state.loading).toBe(false);
      expect(state.error).toBeNull();
      expect(state.scanned).toBe(false);
      expect(state.filterType).toBe("");
      expect(state.filterSearch).toBe("");
    });
  });
});
