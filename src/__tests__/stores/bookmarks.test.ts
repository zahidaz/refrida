import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("react-hot-toast", () => ({
  default: { success: vi.fn(), error: vi.fn() },
}));

import { useBookmarksStore } from "@/stores/bookmarks.ts";

describe("bookmarks store", () => {
  beforeEach(() => {
    useBookmarksStore.setState({ bookmarks: [] });
  });

  describe("add", () => {
    it("adds a bookmark with generated id and timestamp", () => {
      useBookmarksStore.getState().add({ label: "Test", address: "0x1000", type: "hex" });
      const { bookmarks } = useBookmarksStore.getState();
      expect(bookmarks).toHaveLength(1);
      expect(bookmarks[0].label).toBe("Test");
      expect(bookmarks[0].address).toBe("0x1000");
      expect(bookmarks[0].type).toBe("hex");
      expect(bookmarks[0].id).toBeTruthy();
      expect(bookmarks[0].created).toBeTruthy();
    });
  });

  describe("remove", () => {
    it("removes bookmark by id", () => {
      useBookmarksStore.getState().add({ label: "A", address: "0x1", type: "hex" });
      useBookmarksStore.getState().add({ label: "B", address: "0x2", type: "asm" });
      const id = useBookmarksStore.getState().bookmarks[0].id;
      useBookmarksStore.getState().remove(id);
      expect(useBookmarksStore.getState().bookmarks).toHaveLength(1);
      expect(useBookmarksStore.getState().bookmarks[0].label).toBe("B");
    });
  });

  describe("rename", () => {
    it("updates bookmark label", () => {
      useBookmarksStore.getState().add({ label: "Original", address: "0x1", type: "hex" });
      const id = useBookmarksStore.getState().bookmarks[0].id;
      useBookmarksStore.getState().rename(id, "Renamed");
      expect(useBookmarksStore.getState().bookmarks[0].label).toBe("Renamed");
    });
  });
});
