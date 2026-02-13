import { describe, it, expect, beforeEach } from "vitest";
import { useScriptsStore } from "@/stores/scripts.ts";

function resetStore() {
  const id = "test-tab-1";
  useScriptsStore.setState({
    tabs: [{ id, name: "Script 1", type: "code", content: "initial" }],
    activeTabId: id,
    savedScripts: [],
  });
}

describe("scripts store", () => {
  beforeEach(resetStore);

  describe("addTab", () => {
    it("creates a new tab with unique name", () => {
      useScriptsStore.getState().addTab(() => "current");
      const { tabs } = useScriptsStore.getState();
      expect(tabs).toHaveLength(2);
      expect(tabs[1].name).toBe("Script 2");
      expect(tabs[1].type).toBe("code");
    });

    it("avoids name collisions", () => {
      useScriptsStore.setState({
        tabs: [
          { id: "t1", name: "Script 1", type: "code", content: "" },
          { id: "t2", name: "Script 2", type: "code", content: "" },
        ],
        activeTabId: "t1",
      });
      useScriptsStore.getState().addTab(() => "");
      const names = useScriptsStore.getState().tabs.map((t) => t.name);
      expect(names).toContain("Script 3");
    });

    it("sets new tab as active", () => {
      useScriptsStore.getState().addTab(() => "current");
      const { activeTabId, tabs } = useScriptsStore.getState();
      expect(activeTabId).toBe(tabs[tabs.length - 1].id);
    });
  });

  describe("closeTab", () => {
    it("removes tab from list", () => {
      useScriptsStore.getState().addTab(() => "");
      const tabs = useScriptsStore.getState().tabs;
      expect(tabs).toHaveLength(2);
      useScriptsStore.getState().closeTab(tabs[1].id);
      expect(useScriptsStore.getState().tabs).toHaveLength(1);
    });

    it("returns null when only one tab", () => {
      const result = useScriptsStore.getState().closeTab("test-tab-1");
      expect(result).toBeNull();
      expect(useScriptsStore.getState().tabs).toHaveLength(1);
    });

    it("activates adjacent tab when closing active tab", () => {
      useScriptsStore.getState().addTab(() => "");
      const tabs = useScriptsStore.getState().tabs;
      const firstId = tabs[0].id;
      useScriptsStore.getState().closeTab(tabs[1].id);
      expect(useScriptsStore.getState().activeTabId).toBe(firstId);
    });
  });

  describe("renameTab", () => {
    it("updates tab name", () => {
      useScriptsStore.getState().renameTab("test-tab-1", "My Script");
      expect(useScriptsStore.getState().tabs[0].name).toBe("My Script");
    });

    it("ignores empty name", () => {
      useScriptsStore.getState().renameTab("test-tab-1", "  ");
      expect(useScriptsStore.getState().tabs[0].name).toBe("Script 1");
    });
  });

  describe("switchTab", () => {
    it("changes activeTabId", () => {
      useScriptsStore.getState().addTab(() => "");
      const tabs = useScriptsStore.getState().tabs;
      useScriptsStore.getState().switchTab(tabs[0].id, () => "new content");
      expect(useScriptsStore.getState().activeTabId).toBe(tabs[0].id);
    });

    it("does nothing when switching to same tab", () => {
      useScriptsStore.getState().switchTab("test-tab-1", () => "");
      expect(useScriptsStore.getState().activeTabId).toBe("test-tab-1");
    });
  });

  describe("reorderTabs", () => {
    it("moves tab to new position", () => {
      useScriptsStore.getState().addTab(() => "");
      useScriptsStore.getState().addTab(() => "");
      const tabs = useScriptsStore.getState().tabs;
      const ids = tabs.map((t) => t.id);
      useScriptsStore.getState().reorderTabs(ids[2], ids[0]);
      const newIds = useScriptsStore.getState().tabs.map((t) => t.id);
      expect(newIds[0]).toBe(ids[2]);
    });

    it("does nothing when from === to", () => {
      const before = useScriptsStore.getState().tabs;
      useScriptsStore.getState().reorderTabs("test-tab-1", "test-tab-1");
      expect(useScriptsStore.getState().tabs).toEqual(before);
    });
  });

  describe("saveToLibrary / loadFromLibrary / deleteFromLibrary", () => {
    it("saves script to library", () => {
      useScriptsStore.getState().saveToLibrary("code here", "My Saved");
      const { savedScripts } = useScriptsStore.getState();
      expect(savedScripts).toHaveLength(1);
      expect(savedScripts[0].name).toBe("My Saved");
      expect(savedScripts[0].content).toBe("code here");
    });

    it("ignores empty content", () => {
      useScriptsStore.getState().saveToLibrary("  ", "test");
      expect(useScriptsStore.getState().savedScripts).toHaveLength(0);
    });

    it("loads script from library", () => {
      useScriptsStore.getState().saveToLibrary("saved code", "Test");
      const id = useScriptsStore.getState().savedScripts[0].id;
      expect(useScriptsStore.getState().loadFromLibrary(id)).toBe("saved code");
    });

    it("returns null for missing script", () => {
      expect(useScriptsStore.getState().loadFromLibrary("nonexistent")).toBeNull();
    });

    it("deletes script from library", () => {
      useScriptsStore.getState().saveToLibrary("code", "Test");
      const id = useScriptsStore.getState().savedScripts[0].id;
      useScriptsStore.getState().deleteFromLibrary(id);
      expect(useScriptsStore.getState().savedScripts).toHaveLength(0);
    });
  });

  describe("openHexTab", () => {
    it("creates a hex tab", () => {
      useScriptsStore.getState().openHexTab("0x1000", () => "");
      const tabs = useScriptsStore.getState().tabs;
      const hexTab = tabs.find((t) => t.type === "hex");
      expect(hexTab).toBeTruthy();
      expect(hexTab!.address).toBe("0x1000");
      expect(hexTab!.name).toContain("Hex");
    });
  });

  describe("openAsmTab", () => {
    it("creates an asm tab", () => {
      useScriptsStore.getState().openAsmTab("0x2000", () => "");
      const tabs = useScriptsStore.getState().tabs;
      const asmTab = tabs.find((t) => t.type === "asm");
      expect(asmTab).toBeTruthy();
      expect(asmTab!.address).toBe("0x2000");
    });
  });

  describe("openProcessTab", () => {
    it("creates a process tab", () => {
      useScriptsStore.getState().openProcessTab(() => "");
      const tabs = useScriptsStore.getState().tabs;
      expect(tabs.find((t) => t.type === "process")).toBeTruthy();
    });

    it("reuses existing process tab", () => {
      useScriptsStore.getState().openProcessTab(() => "");
      useScriptsStore.getState().openProcessTab(() => "");
      const processTabs = useScriptsStore.getState().tabs.filter((t) => t.type === "process");
      expect(processTabs).toHaveLength(1);
    });
  });

  describe("openFileScanTab", () => {
    it("creates a filescan tab", () => {
      useScriptsStore.getState().openFileScanTab(() => "");
      const tabs = useScriptsStore.getState().tabs;
      expect(tabs.find((t) => t.type === "filescan")).toBeTruthy();
    });

    it("reuses existing filescan tab", () => {
      useScriptsStore.getState().openFileScanTab(() => "");
      useScriptsStore.getState().openFileScanTab(() => "");
      const fscanTabs = useScriptsStore.getState().tabs.filter((t) => t.type === "filescan");
      expect(fscanTabs).toHaveLength(1);
    });
  });

  describe("setTabLanguage", () => {
    it("sets language on tab", () => {
      useScriptsStore.getState().setTabLanguage("test-tab-1", "typescript");
      expect(useScriptsStore.getState().tabs[0].language).toBe("typescript");
    });
  });

  describe("updateTabContent", () => {
    it("updates active tab content", () => {
      useScriptsStore.getState().updateTabContent("new content");
      expect(useScriptsStore.getState().tabs[0].content).toBe("new content");
    });
  });

  describe("getActiveTab", () => {
    it("returns the active tab", () => {
      const tab = useScriptsStore.getState().getActiveTab();
      expect(tab).toBeTruthy();
      expect(tab!.id).toBe("test-tab-1");
    });
  });
});
