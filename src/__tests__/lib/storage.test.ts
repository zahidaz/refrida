import { describe, it, expect, vi } from "vitest";
import { getItem, setItem } from "@/lib/storage.ts";

describe("storage", () => {
  describe("getItem", () => {
    it("returns parsed value from localStorage", () => {
      localStorage.setItem("test-key", JSON.stringify({ foo: "bar" }));
      expect(getItem("test-key", null)).toEqual({ foo: "bar" });
    });

    it("returns fallback when key is missing", () => {
      expect(getItem("nonexistent", "default")).toBe("default");
    });

    it("returns fallback when stored value is invalid JSON", () => {
      localStorage.setItem("bad-json", "not-json{{{");
      expect(getItem("bad-json", [])).toEqual([]);
    });

    it("returns fallback for null stored value", () => {
      expect(getItem("missing", 42)).toBe(42);
    });

    it("handles array values", () => {
      localStorage.setItem("arr", JSON.stringify([1, 2, 3]));
      expect(getItem("arr", [])).toEqual([1, 2, 3]);
    });

    it("handles boolean values", () => {
      localStorage.setItem("bool", JSON.stringify(true));
      expect(getItem("bool", false)).toBe(true);
    });
  });

  describe("setItem", () => {
    it("serializes and stores value", () => {
      setItem("key1", { a: 1 });
      expect(localStorage.getItem("key1")).toBe('{"a":1}');
    });

    it("stores arrays", () => {
      setItem("arr1", [1, 2, 3]);
      expect(localStorage.getItem("arr1")).toBe("[1,2,3]");
    });

    it("handles localStorage quota errors gracefully", () => {
      const origSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = vi.fn(() => {
        throw new DOMException("QuotaExceededError");
      });
      expect(() => setItem("overflow", "x".repeat(1000))).not.toThrow();
      Storage.prototype.setItem = origSetItem;
    });
  });
});
