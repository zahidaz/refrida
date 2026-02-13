import { describe, it, expect, beforeEach } from "vitest";
import { useProcessInfoStore } from "@/stores/processInfo.ts";

describe("processInfo store", () => {
  beforeEach(() => {
    useProcessInfoStore.setState({
      info: null,
      threads: [],
      envVars: [],
      loading: false,
      loadingThreads: false,
      loadingEnv: false,
      error: null,
      activeSection: "overview",
      envFilter: "",
    });
  });

  describe("setActiveSection", () => {
    it("changes to threads", () => {
      useProcessInfoStore.getState().setActiveSection("threads");
      expect(useProcessInfoStore.getState().activeSection).toBe("threads");
    });

    it("changes to env", () => {
      useProcessInfoStore.getState().setActiveSection("env");
      expect(useProcessInfoStore.getState().activeSection).toBe("env");
    });

    it("changes to operations", () => {
      useProcessInfoStore.getState().setActiveSection("operations");
      expect(useProcessInfoStore.getState().activeSection).toBe("operations");
    });
  });

  describe("setEnvFilter", () => {
    it("updates env filter", () => {
      useProcessInfoStore.getState().setEnvFilter("PATH");
      expect(useProcessInfoStore.getState().envFilter).toBe("PATH");
    });
  });

  describe("reset", () => {
    it("clears state", () => {
      useProcessInfoStore.setState({
        info: {
          pid: 1234,
          arch: "arm64",
          platform: "linux",
          pageSize: 4096,
          pointerSize: 8,
          mainModule: { name: "app", base: "0x1000", size: 4096, path: "/app" },
          threadCount: 5,
          moduleCount: 20,
          rangeCount: 100,
          totalMappedSize: 1048576,
          currentThreadId: 1,
        },
        threads: [{ id: 1, state: "running", pc: "0x1000", sp: "0x2000" }],
        envVars: [{ key: "PATH", value: "/usr/bin" }],
        error: "test",
      });
      useProcessInfoStore.getState().reset();
      const state = useProcessInfoStore.getState();
      expect(state.info).toBeNull();
      expect(state.threads).toHaveLength(0);
      expect(state.envVars).toHaveLength(0);
      expect(state.error).toBeNull();
    });
  });
});
