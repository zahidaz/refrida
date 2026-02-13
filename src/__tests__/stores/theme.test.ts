import { describe, it, expect, beforeEach } from "vitest";
import { useThemeStore } from "@/stores/theme.ts";

describe("theme store", () => {
  beforeEach(() => {
    useThemeStore.setState({ dark: false });
    document.documentElement.classList.remove("dark");
  });

  describe("toggle", () => {
    it("toggles from light to dark", () => {
      useThemeStore.getState().toggle();
      expect(useThemeStore.getState().dark).toBe(true);
      expect(document.documentElement.classList.contains("dark")).toBe(true);
    });

    it("toggles from dark to light", () => {
      useThemeStore.setState({ dark: true });
      document.documentElement.classList.add("dark");
      useThemeStore.getState().toggle();
      expect(useThemeStore.getState().dark).toBe(false);
      expect(document.documentElement.classList.contains("dark")).toBe(false);
    });

    it("persists theme to localStorage", () => {
      useThemeStore.getState().toggle();
      expect(localStorage.getItem("refrida-theme")).toBe("dark");
      useThemeStore.getState().toggle();
      expect(localStorage.getItem("refrida-theme")).toBe("light");
    });
  });
});
