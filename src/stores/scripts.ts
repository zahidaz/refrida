import { create } from "zustand";
import { getItem, setItem } from "@/lib/storage.ts";

const TABS_KEY = "refrida-tabs";
const SCRIPTS_KEY = "refrida-scripts";

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

export interface ScriptTab {
  id: string;
  name: string;
  content: string;
}

export interface SavedScript {
  id: string;
  name: string;
  content: string;
  date: string;
}

interface TabsData {
  tabs: ScriptTab[];
  activeTabId: string;
}

interface ScriptsState {
  tabs: ScriptTab[];
  activeTabId: string;
  savedScripts: SavedScript[];
  loadState: () => void;
  syncCurrentTab: (content: string) => void;
  switchTab: (id: string, getCurrentContent: () => string) => void;
  addTab: (getCurrentContent: () => string) => void;
  closeTab: (id: string) => string | null;
  renameTab: (id: string, newName: string) => void;
  saveToLibrary: (content: string) => void;
  loadFromLibrary: (id: string) => string | null;
  deleteFromLibrary: (id: string) => void;
  updateTabContent: (content: string) => void;
  getActiveTab: () => ScriptTab | undefined;
}

export const useScriptsStore = create<ScriptsState>((set, get) => ({
  tabs: [{ id: generateId(), name: "Script 1", content: "" }],
  activeTabId: "",
  savedScripts: [],

  loadState: () => {
    const saved = getItem<TabsData | null>(TABS_KEY, null);
    if (saved?.tabs?.length) {
      set({
        tabs: saved.tabs,
        activeTabId: saved.activeTabId || saved.tabs[0].id,
      });
    } else {
      const id = generateId();
      set({
        tabs: [{ id, name: "Script 1", content: "" }],
        activeTabId: id,
      });
    }
    set({
      savedScripts: getItem<SavedScript[]>(SCRIPTS_KEY, []),
    });
  },

  syncCurrentTab: (content) => {
    set((state) => {
      const tabs = state.tabs.map((t) =>
        t.id === state.activeTabId ? { ...t, content } : t,
      );
      setItem(TABS_KEY, { tabs, activeTabId: state.activeTabId });
      return { tabs };
    });
  },

  switchTab: (id, getCurrentContent) => {
    const state = get();
    if (id === state.activeTabId) return;
    const tabs = state.tabs.map((t) =>
      t.id === state.activeTabId
        ? { ...t, content: getCurrentContent() }
        : t,
    );
    set({ tabs, activeTabId: id });
    setItem(TABS_KEY, { tabs, activeTabId: id });
  },

  addTab: (getCurrentContent) => {
    const state = get();
    const tabs = state.tabs.map((t) =>
      t.id === state.activeTabId
        ? { ...t, content: getCurrentContent() }
        : t,
    );
    const id = generateId();
    const newTab: ScriptTab = {
      id,
      name: `Script ${tabs.length + 1}`,
      content: "",
    };
    const newTabs = [...tabs, newTab];
    set({ tabs: newTabs, activeTabId: id });
    setItem(TABS_KEY, { tabs: newTabs, activeTabId: id });
  },

  closeTab: (id) => {
    const state = get();
    if (state.tabs.length <= 1) return null;
    const idx = state.tabs.findIndex((t) => t.id === id);
    const newTabs = state.tabs.filter((t) => t.id !== id);
    let newActiveId = state.activeTabId;
    let switchContent: string | null = null;
    if (state.activeTabId === id) {
      const newIdx = Math.min(idx, newTabs.length - 1);
      newActiveId = newTabs[newIdx].id;
      switchContent = newTabs[newIdx].content;
    }
    set({ tabs: newTabs, activeTabId: newActiveId });
    setItem(TABS_KEY, { tabs: newTabs, activeTabId: newActiveId });
    return switchContent;
  },

  renameTab: (id, newName) => {
    if (!newName.trim()) return;
    set((state) => {
      const tabs = state.tabs.map((t) =>
        t.id === id ? { ...t, name: newName.trim() } : t,
      );
      setItem(TABS_KEY, { tabs, activeTabId: state.activeTabId });
      return { tabs };
    });
  },

  saveToLibrary: (content) => {
    if (!content.trim()) return;
    const name = prompt("Save script as:");
    if (!name?.trim()) return;
    set((state) => {
      const savedScripts = [
        ...state.savedScripts,
        {
          id: generateId(),
          name: name.trim(),
          content,
          date: new Date().toISOString(),
        },
      ];
      setItem(SCRIPTS_KEY, savedScripts);
      return { savedScripts };
    });
  },

  loadFromLibrary: (id) => {
    const script = get().savedScripts.find((s) => s.id === id);
    if (!script) return null;
    return script.content;
  },

  deleteFromLibrary: (id) => {
    set((state) => {
      const savedScripts = state.savedScripts.filter((s) => s.id !== id);
      setItem(SCRIPTS_KEY, savedScripts);
      return { savedScripts };
    });
  },

  updateTabContent: (content) => {
    set((state) => {
      const tabs = state.tabs.map((t) =>
        t.id === state.activeTabId ? { ...t, content } : t,
      );
      setItem(TABS_KEY, { tabs, activeTabId: state.activeTabId });
      return { tabs };
    });
  },

  getActiveTab: () => {
    const state = get();
    return state.tabs.find((t) => t.id === state.activeTabId);
  },
}));
