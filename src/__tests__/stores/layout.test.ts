import { describe, it, expect, beforeEach } from "vitest";
import { useLayoutStore } from "@/stores/layout.ts";

describe("layout store", () => {
  beforeEach(() => {
    useLayoutStore.setState({
      activeActivity: "scripts",
      sidePanelVisible: false,
      sidePanelWidth: 300,
      bottomPanelVisible: true,
      commandPaletteOpen: false,
      connectionDialogOpen: false,
      processPickerOpen: false,
      aboutOpen: false,
      welcomeOpen: true,
      templateBrowserOpen: false,
    });
  });

  describe("toggleActivity", () => {
    it("shows panel and sets activity when panel is hidden", () => {
      useLayoutStore.getState().toggleActivity("modules");
      const state = useLayoutStore.getState();
      expect(state.activeActivity).toBe("modules");
      expect(state.sidePanelVisible).toBe(true);
    });

    it("hides panel when same activity is toggled while visible", () => {
      useLayoutStore.setState({ sidePanelVisible: true, activeActivity: "modules" });
      useLayoutStore.getState().toggleActivity("modules");
      expect(useLayoutStore.getState().sidePanelVisible).toBe(false);
    });

    it("switches activity when different activity is clicked while visible", () => {
      useLayoutStore.setState({ sidePanelVisible: true, activeActivity: "scripts" });
      useLayoutStore.getState().toggleActivity("memory");
      const state = useLayoutStore.getState();
      expect(state.activeActivity).toBe("memory");
      expect(state.sidePanelVisible).toBe(true);
    });
  });

  describe("toggleSidePanel", () => {
    it("toggles side panel visibility", () => {
      useLayoutStore.getState().toggleSidePanel();
      expect(useLayoutStore.getState().sidePanelVisible).toBe(true);
      useLayoutStore.getState().toggleSidePanel();
      expect(useLayoutStore.getState().sidePanelVisible).toBe(false);
    });
  });

  describe("toggleBottomPanel", () => {
    it("toggles bottom panel visibility", () => {
      useLayoutStore.getState().toggleBottomPanel();
      expect(useLayoutStore.getState().bottomPanelVisible).toBe(false);
      useLayoutStore.getState().toggleBottomPanel();
      expect(useLayoutStore.getState().bottomPanelVisible).toBe(true);
    });
  });

  describe("dialog controls", () => {
    it("opens and closes command palette", () => {
      useLayoutStore.getState().setCommandPaletteOpen(true);
      expect(useLayoutStore.getState().commandPaletteOpen).toBe(true);
      useLayoutStore.getState().setCommandPaletteOpen(false);
      expect(useLayoutStore.getState().commandPaletteOpen).toBe(false);
    });

    it("opens and closes connection dialog", () => {
      useLayoutStore.getState().setConnectionDialogOpen(true);
      expect(useLayoutStore.getState().connectionDialogOpen).toBe(true);
    });

    it("opens and closes about dialog", () => {
      useLayoutStore.getState().setAboutOpen(true);
      expect(useLayoutStore.getState().aboutOpen).toBe(true);
    });
  });
});
