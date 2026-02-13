import { create } from "zustand";

interface ThemeState {
  dark: boolean;
  toggle: () => void;
}

function getInitialTheme(): boolean {
  const saved = localStorage.getItem("refrida-theme");
  if (saved) return saved === "dark";
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export const useThemeStore = create<ThemeState>((set) => ({
  dark: getInitialTheme(),
  toggle: () =>
    set((state) => {
      const next = !state.dark;
      document.documentElement.classList.toggle("dark", next);
      localStorage.setItem("refrida-theme", next ? "dark" : "light");
      return { dark: next };
    }),
}));
