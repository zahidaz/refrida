import { describe, it, expect, beforeEach } from "vitest";
import { useReplStore } from "@/stores/repl.ts";

describe("repl store", () => {
  beforeEach(() => {
    useReplStore.setState({
      history: [],
      historyIndex: -1,
      input: "",
      running: false,
    });
  });

  describe("historyUp", () => {
    it("navigates backward through history", () => {
      useReplStore.setState({ history: ["cmd3", "cmd2", "cmd1"] });
      useReplStore.getState().historyUp();
      expect(useReplStore.getState().input).toBe("cmd3");
      expect(useReplStore.getState().historyIndex).toBe(0);
      useReplStore.getState().historyUp();
      expect(useReplStore.getState().input).toBe("cmd2");
      expect(useReplStore.getState().historyIndex).toBe(1);
    });

    it("stops at end of history", () => {
      useReplStore.setState({ history: ["only"] });
      useReplStore.getState().historyUp();
      useReplStore.getState().historyUp();
      expect(useReplStore.getState().historyIndex).toBe(0);
      expect(useReplStore.getState().input).toBe("only");
    });

    it("does nothing with empty history", () => {
      useReplStore.getState().historyUp();
      expect(useReplStore.getState().historyIndex).toBe(-1);
    });
  });

  describe("historyDown", () => {
    it("navigates forward through history", () => {
      useReplStore.setState({ history: ["cmd3", "cmd2", "cmd1"], historyIndex: 2 });
      useReplStore.getState().historyDown();
      expect(useReplStore.getState().input).toBe("cmd2");
      useReplStore.getState().historyDown();
      expect(useReplStore.getState().input).toBe("cmd3");
    });

    it("clears input when reaching index 0", () => {
      useReplStore.setState({ history: ["cmd1"], historyIndex: 0 });
      useReplStore.getState().historyDown();
      expect(useReplStore.getState().input).toBe("");
      expect(useReplStore.getState().historyIndex).toBe(-1);
    });

    it("does nothing at index -1", () => {
      useReplStore.getState().historyDown();
      expect(useReplStore.getState().historyIndex).toBe(-1);
    });
  });

  describe("setInput", () => {
    it("updates input", () => {
      useReplStore.getState().setInput("new text");
      expect(useReplStore.getState().input).toBe("new text");
    });
  });

  describe("reset", () => {
    it("clears all state", () => {
      useReplStore.setState({ history: ["a", "b"], historyIndex: 1, input: "x", running: true });
      useReplStore.getState().reset();
      const state = useReplStore.getState();
      expect(state.history).toEqual([]);
      expect(state.historyIndex).toBe(-1);
      expect(state.input).toBe("");
      expect(state.running).toBe(false);
    });
  });
});
