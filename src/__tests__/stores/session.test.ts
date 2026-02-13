import { describe, it, expect, beforeEach } from "vitest";
import { useSessionStore } from "@/stores/session.ts";

describe("session store", () => {
  beforeEach(() => {
    useSessionStore.setState({
      sessionActive: false,
      scriptActive: false,
      sessionInfoText: "",
      attachedPid: null,
      attachedName: "",
      scriptRuntime: "default",
      lastCrash: null,
      busy: false,
      busyLabel: "",
    });
  });

  describe("setScriptRuntime", () => {
    it("updates script runtime", () => {
      useSessionStore.getState().setScriptRuntime("qjs");
      expect(useSessionStore.getState().scriptRuntime).toBe("qjs");
    });
  });

  describe("runScript guard", () => {
    it("shows error when no session", async () => {
      await useSessionStore.getState().runScript("console.log('test')");
      expect(useSessionStore.getState().scriptActive).toBe(false);
    });

    it("skips when busy", async () => {
      useSessionStore.setState({ busy: true });
      await useSessionStore.getState().runScript("console.log('test')");
      expect(useSessionStore.getState().scriptActive).toBe(false);
    });
  });

  describe("attachToProcess guard", () => {
    it("skips when busy", async () => {
      useSessionStore.setState({ busy: true });
      await useSessionStore.getState().attachToProcess(1234, "test");
      expect(useSessionStore.getState().sessionActive).toBe(false);
    });
  });

  describe("cancelBusy", () => {
    it("can be called safely when not busy", () => {
      expect(() => useSessionStore.getState().cancelBusy()).not.toThrow();
    });
  });

  describe("reset", () => {
    it("clears all state", () => {
      useSessionStore.setState({
        sessionActive: true,
        scriptActive: true,
        attachedPid: 1234,
        attachedName: "test",
        sessionInfoText: "test (PID 1234)",
        busy: true,
        busyLabel: "Loading...",
      });
      useSessionStore.getState().reset();
      const state = useSessionStore.getState();
      expect(state.sessionActive).toBe(false);
      expect(state.scriptActive).toBe(false);
      expect(state.attachedPid).toBeNull();
      expect(state.attachedName).toBe("");
      expect(state.busy).toBe(false);
    });
  });
});
