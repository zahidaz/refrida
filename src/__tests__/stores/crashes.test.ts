import { describe, it, expect, beforeEach } from "vitest";
import { useCrashesStore } from "@/stores/crashes.ts";

describe("crashes store", () => {
  beforeEach(() => {
    useCrashesStore.setState({ crashes: [], expanded: null, hasNew: false });
  });

  describe("addCrash", () => {
    it("adds crash with id and timestamp", () => {
      useCrashesStore.getState().addCrash("TestApp", 123, "terminated", { summary: "SIGSEGV" });
      const { crashes } = useCrashesStore.getState();
      expect(crashes).toHaveLength(1);
      expect(crashes[0].processName).toBe("TestApp");
      expect(crashes[0].pid).toBe(123);
      expect(crashes[0].reason).toBe("terminated");
      expect(crashes[0].summary).toBe("SIGSEGV");
      expect(crashes[0].id).toBeTruthy();
    });

    it("prepends new crashes", () => {
      useCrashesStore.getState().addCrash("App1", 1, "r1", { summary: "s1" });
      useCrashesStore.getState().addCrash("App2", 2, "r2", { summary: "s2" });
      expect(useCrashesStore.getState().crashes[0].processName).toBe("App2");
    });

    it("sets hasNew to true", () => {
      useCrashesStore.getState().addCrash("App", 1, "r", { summary: "s" });
      expect(useCrashesStore.getState().hasNew).toBe(true);
    });

    it("caps at 100 crashes", () => {
      for (let i = 0; i < 110; i++) {
        useCrashesStore.getState().addCrash(`App${i}`, i, "r", { summary: "s" });
      }
      expect(useCrashesStore.getState().crashes).toHaveLength(100);
    });
  });

  describe("toggleExpand", () => {
    it("expands a crash", () => {
      useCrashesStore.getState().addCrash("App", 1, "r", { summary: "s" });
      const id = useCrashesStore.getState().crashes[0].id;
      useCrashesStore.getState().toggleExpand(id);
      expect(useCrashesStore.getState().expanded).toBe(id);
    });

    it("collapses when toggled again", () => {
      useCrashesStore.getState().addCrash("App", 1, "r", { summary: "s" });
      const id = useCrashesStore.getState().crashes[0].id;
      useCrashesStore.getState().toggleExpand(id);
      useCrashesStore.getState().toggleExpand(id);
      expect(useCrashesStore.getState().expanded).toBeNull();
    });
  });

  describe("clearBadge", () => {
    it("sets hasNew to false", () => {
      useCrashesStore.setState({ hasNew: true });
      useCrashesStore.getState().clearBadge();
      expect(useCrashesStore.getState().hasNew).toBe(false);
    });
  });

  describe("clearAll", () => {
    it("removes all crashes", () => {
      useCrashesStore.getState().addCrash("App", 1, "r", { summary: "s" });
      useCrashesStore.getState().clearAll();
      expect(useCrashesStore.getState().crashes).toHaveLength(0);
      expect(useCrashesStore.getState().hasNew).toBe(false);
    });
  });
});
