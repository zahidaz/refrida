import { create } from "zustand";
import { getItem, setItem } from "@/lib/storage.ts";

export type Activity = "scripts" | "settings";

interface LayoutState {
  activeActivity: Activity;
  sidePanelVisible: boolean;
  sidePanelWidth: number;
  bottomPanelVisible: boolean;
  bottomPanelHeight: number;
  commandPaletteOpen: boolean;
  connectionDialogOpen: boolean;
  processPickerOpen: boolean;
  aboutOpen: boolean;
  welcomeOpen: boolean;
  setActiveActivity: (activity: Activity) => void;
  toggleActivity: (activity: Activity) => void;
  setSidePanelVisible: (v: boolean) => void;
  setSidePanelWidth: (w: number) => void;
  setBottomPanelVisible: (v: boolean) => void;
  setBottomPanelHeight: (h: number) => void;
  toggleSidePanel: () => void;
  toggleBottomPanel: () => void;
  setCommandPaletteOpen: (v: boolean) => void;
  setConnectionDialogOpen: (v: boolean) => void;
  setProcessPickerOpen: (v: boolean) => void;
  setAboutOpen: (v: boolean) => void;
  setWelcomeOpen: (v: boolean) => void;
}

export const useLayoutStore = create<LayoutState>((set, get) => ({
  activeActivity: "scripts",
  sidePanelVisible: getItem("refrida-side-panel-visible", false),
  sidePanelWidth: getItem("refrida-side-panel-width", 300),
  bottomPanelVisible: getItem("refrida-bottom-panel-visible", true),
  bottomPanelHeight: getItem("refrida-bottom-panel-height", 45),
  commandPaletteOpen: false,
  connectionDialogOpen: false,
  processPickerOpen: false,
  aboutOpen: false,
  welcomeOpen: getItem("refrida-welcome-open", true),

  setActiveActivity: (activeActivity) => set({ activeActivity }),

  toggleActivity: (activity) => {
    const { activeActivity, sidePanelVisible } = get();
    if (activeActivity === activity && sidePanelVisible) {
      set({ sidePanelVisible: false });
      setItem("refrida-side-panel-visible", false);
    } else {
      set({ activeActivity: activity, sidePanelVisible: true });
      setItem("refrida-side-panel-visible", true);
    }
  },

  setSidePanelVisible: (sidePanelVisible) => {
    set({ sidePanelVisible });
    setItem("refrida-side-panel-visible", sidePanelVisible);
  },

  setSidePanelWidth: (sidePanelWidth) => {
    set({ sidePanelWidth });
    setItem("refrida-side-panel-width", sidePanelWidth);
  },

  setBottomPanelVisible: (bottomPanelVisible) => {
    set({ bottomPanelVisible });
    setItem("refrida-bottom-panel-visible", bottomPanelVisible);
  },

  setBottomPanelHeight: (bottomPanelHeight) => {
    set({ bottomPanelHeight });
    setItem("refrida-bottom-panel-height", bottomPanelHeight);
  },

  toggleSidePanel: () => {
    const next = !get().sidePanelVisible;
    set({ sidePanelVisible: next });
    setItem("refrida-side-panel-visible", next);
  },

  toggleBottomPanel: () => {
    const next = !get().bottomPanelVisible;
    set({ bottomPanelVisible: next });
    setItem("refrida-bottom-panel-visible", next);
  },

  setCommandPaletteOpen: (commandPaletteOpen) => set({ commandPaletteOpen }),
  setConnectionDialogOpen: (connectionDialogOpen) =>
    set({ connectionDialogOpen }),
  setProcessPickerOpen: (processPickerOpen) => set({ processPickerOpen }),
  setAboutOpen: (aboutOpen) => set({ aboutOpen }),
  setWelcomeOpen: (welcomeOpen) => {
    set({ welcomeOpen });
    setItem("refrida-welcome-open", welcomeOpen);
  },
}));
