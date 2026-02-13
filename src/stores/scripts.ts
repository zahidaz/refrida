import { create } from "zustand";
import { getItem, setItem } from "@/lib/storage.ts";

const TABS_KEY = "refrida-tabs";
const SCRIPTS_KEY = "refrida-scripts";

const STARTER_CODE = `send("Hello from Frida!");

Process.enumerateModules().slice(0, 10).forEach(m => {
  send({ name: m.name, base: m.base.toString(), size: m.size });
});`;

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

export type TabType = "code" | "hex" | "asm";

export interface ScriptTab {
  id: string;
  name: string;
  type: TabType;
  content: string;
  address?: string;
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
  saveToLibrary: (content: string, name: string) => void;
  loadFromLibrary: (id: string) => string | null;
  deleteFromLibrary: (id: string) => void;
  openInNewTab: (name: string, content: string, getCurrentContent: () => string) => void;
  openHexTab: (address: string, getCurrentContent: () => string) => void;
  openAsmTab: (address: string, getCurrentContent: () => string) => void;
  reorderTabs: (fromId: string, toId: string) => void;
  updateTabContent: (content: string) => void;
  getActiveTab: () => ScriptTab | undefined;
}

export const useScriptsStore = create<ScriptsState>((set, get) => ({
  tabs: [{ id: generateId(), name: "Script 1", type: "code" as TabType, content: STARTER_CODE }],
  activeTabId: "",
  savedScripts: [],

  loadState: () => {
    const saved = getItem<TabsData | null>(TABS_KEY, null);
    if (saved?.tabs?.length) {
      const tabs = saved.tabs.map((t) => ({ ...t, type: t.type || ("code" as TabType) }));
      set({
        tabs,
        activeTabId: saved.activeTabId || tabs[0].id,
      });
    } else {
      const id = generateId();
      set({
        tabs: [{ id, name: "Script 1", type: "code" as TabType, content: STARTER_CODE }],
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
    const existing = new Set(tabs.map((t) => t.name));
    let n = 1;
    while (existing.has(`Script ${n}`)) n++;
    const newTab: ScriptTab = {
      id,
      name: `Script ${n}`,
      type: "code",
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

  saveToLibrary: (content, name) => {
    if (!content.trim() || !name?.trim()) return;
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

  openInNewTab: (name, content, getCurrentContent) => {
    const state = get();
    const tabs = state.tabs.map((t) =>
      t.id === state.activeTabId
        ? { ...t, content: getCurrentContent() }
        : t,
    );
    const id = generateId();
    const newTab: ScriptTab = { id, name, type: "code", content };
    const newTabs = [...tabs, newTab];
    set({ tabs: newTabs, activeTabId: id });
    setItem(TABS_KEY, { tabs: newTabs, activeTabId: id });
  },

  openHexTab: (address, getCurrentContent) => {
    const state = get();
    const tabs = state.tabs.map((t) =>
      t.id === state.activeTabId && t.type === "code"
        ? { ...t, content: getCurrentContent() }
        : t,
    );
    const id = generateId();
    const label = address ? `Hex: ${address}` : "Hex Viewer";
    const newTab: ScriptTab = { id, name: label, type: "hex", content: "", address };
    const newTabs = [...tabs, newTab];
    set({ tabs: newTabs, activeTabId: id });
    setItem(TABS_KEY, { tabs: newTabs, activeTabId: id });
  },

  openAsmTab: (address, getCurrentContent) => {
    const state = get();
    const tabs = state.tabs.map((t) =>
      t.id === state.activeTabId && t.type === "code"
        ? { ...t, content: getCurrentContent() }
        : t,
    );
    const id = generateId();
    const label = address ? `ASM: ${address}` : "Disassembler";
    const newTab: ScriptTab = { id, name: label, type: "asm", content: "", address };
    const newTabs = [...tabs, newTab];
    set({ tabs: newTabs, activeTabId: id });
    setItem(TABS_KEY, { tabs: newTabs, activeTabId: id });
  },

  reorderTabs: (fromId, toId) => {
    if (fromId === toId) return;
    set((state) => {
      const tabs = [...state.tabs];
      const fromIdx = tabs.findIndex((t) => t.id === fromId);
      const toIdx = tabs.findIndex((t) => t.id === toId);
      if (fromIdx === -1 || toIdx === -1) return state;
      const [moved] = tabs.splice(fromIdx, 1);
      tabs.splice(toIdx, 0, moved);
      setItem(TABS_KEY, { tabs, activeTabId: state.activeTabId });
      return { tabs };
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
