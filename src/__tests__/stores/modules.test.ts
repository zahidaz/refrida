import { describe, it, expect, beforeEach } from "vitest";
import { useModulesStore, getFilteredModules, type ModuleInfo } from "@/stores/modules.ts";

const MOCK_MODULES: ModuleInfo[] = [
  { name: "libc.so", base: "0x7000", size: 4096, path: "/system/lib/libc.so" },
  { name: "libssl.so", base: "0x8000", size: 2048, path: "/system/lib/libssl.so" },
  { name: "app.so", base: "0x9000", size: 1024, path: "/data/app/app.so" },
];

describe("modules store", () => {
  beforeEach(() => {
    useModulesStore.setState({
      modules: MOCK_MODULES,
      expandedModule: null,
      expandedModuleName: null,
      moduleTab: "exports",
      detailFilter: "",
      exports: {},
      imports: {},
      symbols: {},
      ranges: {},
      search: "",
      loading: false,
      loadingDetail: false,
      dumping: false,
    });
  });

  describe("getFilteredModules", () => {
    it("returns all modules when no search", () => {
      const result = getFilteredModules(useModulesStore.getState());
      expect(result).toHaveLength(3);
    });

    it("filters by name", () => {
      useModulesStore.setState({ search: "libc" });
      const result = getFilteredModules(useModulesStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("libc.so");
    });

    it("filters by path", () => {
      useModulesStore.setState({ search: "/data" });
      const result = getFilteredModules(useModulesStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("app.so");
    });

    it("case insensitive", () => {
      useModulesStore.setState({ search: "LIBSSL" });
      const result = getFilteredModules(useModulesStore.getState());
      expect(result).toHaveLength(1);
    });

    it("returns empty for no match", () => {
      useModulesStore.setState({ search: "nonexistent" });
      const result = getFilteredModules(useModulesStore.getState());
      expect(result).toHaveLength(0);
    });
  });

  describe("toggleModule", () => {
    it("expands a module", () => {
      useModulesStore.getState().toggleModule("libc.so", "0x7000");
      expect(useModulesStore.getState().expandedModule).toBe("0x7000");
      expect(useModulesStore.getState().expandedModuleName).toBe("libc.so");
    });

    it("collapses same module", () => {
      useModulesStore.getState().toggleModule("libc.so", "0x7000");
      useModulesStore.getState().toggleModule("libc.so", "0x7000");
      expect(useModulesStore.getState().expandedModule).toBeNull();
    });

    it("switches to different module", () => {
      useModulesStore.getState().toggleModule("libc.so", "0x7000");
      useModulesStore.getState().toggleModule("app.so", "0x9000");
      expect(useModulesStore.getState().expandedModule).toBe("0x9000");
      expect(useModulesStore.getState().expandedModuleName).toBe("app.so");
    });
  });

  describe("setModuleTab", () => {
    it("changes the module tab", () => {
      useModulesStore.getState().setModuleTab("imports");
      expect(useModulesStore.getState().moduleTab).toBe("imports");
    });

    it("clears detail filter", () => {
      useModulesStore.setState({ detailFilter: "test" });
      useModulesStore.getState().setModuleTab("symbols");
      expect(useModulesStore.getState().detailFilter).toBe("");
    });
  });

  describe("setSearch", () => {
    it("updates search", () => {
      useModulesStore.getState().setSearch("test");
      expect(useModulesStore.getState().search).toBe("test");
    });
  });

  describe("reset", () => {
    it("clears all state", () => {
      useModulesStore.setState({
        modules: MOCK_MODULES,
        expandedModule: "0x7000",
        search: "test",
        loading: true,
      });
      useModulesStore.getState().reset();
      const state = useModulesStore.getState();
      expect(state.modules).toHaveLength(0);
      expect(state.expandedModule).toBeNull();
      expect(state.search).toBe("");
      expect(state.loading).toBe(false);
    });
  });
});
