import { describe, it, expect, beforeEach } from "vitest";
import { useDisasmStore } from "@/stores/disasm.ts";

describe("disasm store", () => {
  beforeEach(() => {
    useDisasmStore.setState({ tabStates: {} });
  });

  describe("getTabState", () => {
    it("returns defaults for unknown tab", () => {
      const ts = useDisasmStore.getState().getTabState("unknown");
      expect(ts.address).toBe("");
      expect(ts.count).toBe(100);
      expect(ts.instructions).toHaveLength(0);
      expect(ts.loading).toBe(false);
    });

    it("returns stored state for known tab", () => {
      useDisasmStore.setState({
        tabStates: {
          tab1: {
            address: "0x1000",
            count: 50,
            instructions: [],
            currentAddress: "0x1000",
            selectedIndex: null,
            loading: false,
            error: null,
          },
        },
      });
      const ts = useDisasmStore.getState().getTabState("tab1");
      expect(ts.address).toBe("0x1000");
      expect(ts.count).toBe(50);
    });
  });

  describe("setAddress", () => {
    it("updates address for a tab", () => {
      useDisasmStore.getState().setAddress("tab1", "0xDEAD");
      expect(useDisasmStore.getState().getTabState("tab1").address).toBe("0xDEAD");
    });
  });

  describe("setCount", () => {
    it("updates count for a tab", () => {
      useDisasmStore.getState().setCount("tab1", 200);
      expect(useDisasmStore.getState().getTabState("tab1").count).toBe(200);
    });
  });

  describe("setSelectedIndex", () => {
    it("updates selected index", () => {
      useDisasmStore.getState().setSelectedIndex("tab1", 5);
      expect(useDisasmStore.getState().getTabState("tab1").selectedIndex).toBe(5);
    });

    it("clears selected index with null", () => {
      useDisasmStore.getState().setSelectedIndex("tab1", 5);
      useDisasmStore.getState().setSelectedIndex("tab1", null);
      expect(useDisasmStore.getState().getTabState("tab1").selectedIndex).toBeNull();
    });
  });

  describe("removeTab", () => {
    it("removes tab state", () => {
      useDisasmStore.getState().setAddress("tab1", "0x1000");
      useDisasmStore.getState().setAddress("tab2", "0x2000");
      useDisasmStore.getState().removeTab("tab1");
      expect(useDisasmStore.getState().tabStates["tab1"]).toBeUndefined();
      expect(useDisasmStore.getState().tabStates["tab2"]).toBeDefined();
    });
  });

  describe("reset", () => {
    it("clears all tab states", () => {
      useDisasmStore.getState().setAddress("tab1", "0x1000");
      useDisasmStore.getState().setAddress("tab2", "0x2000");
      useDisasmStore.getState().reset();
      expect(Object.keys(useDisasmStore.getState().tabStates)).toHaveLength(0);
    });
  });
});
