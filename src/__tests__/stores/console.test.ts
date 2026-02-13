import { describe, it, expect, beforeEach } from "vitest";
import { useConsoleStore, getFilteredLines, getRunIds, consoleLineColor, isJson } from "@/stores/console.ts";

describe("console store", () => {
  beforeEach(() => {
    useConsoleStore.setState({
      lines: [],
      search: "",
      filter: "all",
      filterRunId: null,
      currentRunId: 0,
      exportFormat: "txt",
      copiedIndex: null,
    });
  });

  describe("append", () => {
    it("adds a line with correct level and runId", () => {
      useConsoleStore.getState().append("hello", "info");
      const { lines } = useConsoleStore.getState();
      expect(lines).toHaveLength(1);
      expect(lines[0].text).toBe("hello");
      expect(lines[0].level).toBe("info");
      expect(lines[0].runId).toBe(0);
      expect(lines[0].timestamp).toBeTruthy();
    });

    it("defaults to info level", () => {
      useConsoleStore.getState().append("test");
      expect(useConsoleStore.getState().lines[0].level).toBe("info");
    });

    it("appends multiple lines", () => {
      const { append } = useConsoleStore.getState();
      append("line 1");
      append("line 2", "error");
      append("line 3", "warning");
      expect(useConsoleStore.getState().lines).toHaveLength(3);
    });
  });

  describe("bumpRunId", () => {
    it("increments currentRunId", () => {
      useConsoleStore.getState().bumpRunId();
      expect(useConsoleStore.getState().currentRunId).toBe(1);
      useConsoleStore.getState().bumpRunId();
      expect(useConsoleStore.getState().currentRunId).toBe(2);
    });

    it("new lines use bumped runId", () => {
      useConsoleStore.getState().bumpRunId();
      useConsoleStore.getState().append("after bump");
      expect(useConsoleStore.getState().lines[0].runId).toBe(1);
    });
  });

  describe("clear", () => {
    it("empties lines and resets filterRunId", () => {
      useConsoleStore.getState().append("something");
      useConsoleStore.getState().setFilterRunId(1);
      useConsoleStore.getState().clear();
      const state = useConsoleStore.getState();
      expect(state.lines).toHaveLength(0);
      expect(state.filterRunId).toBeNull();
    });
  });

  describe("getFilteredLines", () => {
    it("returns all lines when no filters", () => {
      useConsoleStore.getState().append("a");
      useConsoleStore.getState().append("b");
      const state = useConsoleStore.getState();
      expect(getFilteredLines(state)).toHaveLength(2);
    });

    it("filters by level", () => {
      const { append } = useConsoleStore.getState();
      append("info msg", "info");
      append("error msg", "error");
      append("another info", "info");
      const state = { ...useConsoleStore.getState(), filter: "error" as const };
      const result = getFilteredLines(state);
      expect(result).toHaveLength(1);
      expect(result[0].text).toBe("error msg");
    });

    it("filters by search text (case-insensitive)", () => {
      const { append } = useConsoleStore.getState();
      append("Hello World");
      append("foo bar");
      append("HELLO again");
      const state = { ...useConsoleStore.getState(), search: "hello" };
      expect(getFilteredLines(state)).toHaveLength(2);
    });

    it("filters by runId", () => {
      useConsoleStore.getState().append("run0");
      useConsoleStore.getState().bumpRunId();
      useConsoleStore.getState().append("run1");
      const state = { ...useConsoleStore.getState(), filterRunId: 1 };
      const result = getFilteredLines(state);
      expect(result).toHaveLength(1);
      expect(result[0].text).toBe("run1");
    });

    it("combines multiple filters", () => {
      useConsoleStore.getState().append("error in run0", "error");
      useConsoleStore.getState().bumpRunId();
      useConsoleStore.getState().append("error in run1", "error");
      useConsoleStore.getState().append("info in run1", "info");
      const state = {
        ...useConsoleStore.getState(),
        filter: "error" as const,
        filterRunId: 1,
      };
      const result = getFilteredLines(state);
      expect(result).toHaveLength(1);
      expect(result[0].text).toBe("error in run1");
    });
  });

  describe("getRunIds", () => {
    it("returns unique run IDs sorted descending", () => {
      useConsoleStore.getState().append("a");
      useConsoleStore.getState().bumpRunId();
      useConsoleStore.getState().append("b");
      useConsoleStore.getState().bumpRunId();
      useConsoleStore.getState().append("c");
      expect(getRunIds(useConsoleStore.getState())).toEqual([2, 1, 0]);
    });

    it("returns empty array when no lines", () => {
      expect(getRunIds(useConsoleStore.getState())).toEqual([]);
    });
  });

  describe("consoleLineColor", () => {
    it("maps warning to accent", () => {
      expect(consoleLineColor("warning")).toBe("var(--accent-text)");
    });

    it("maps error to red", () => {
      expect(consoleLineColor("error")).toBe("#ef4444");
    });

    it("maps system to muted", () => {
      expect(consoleLineColor("system")).toBe("var(--text-muted)");
    });

    it("maps info to primary", () => {
      expect(consoleLineColor("info")).toBe("var(--text-primary)");
    });
  });

  describe("isJson", () => {
    it("returns true for valid JSON object", () => {
      expect(isJson('{"a": 1}')).toBe(true);
    });

    it("returns true for valid JSON array", () => {
      expect(isJson("[1, 2, 3]")).toBe(true);
    });

    it("returns false for plain text", () => {
      expect(isJson("hello world")).toBe(false);
    });

    it("returns false for invalid JSON that looks like JSON", () => {
      expect(isJson("{invalid}")).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(isJson("")).toBe(false);
    });

    it("handles whitespace around JSON", () => {
      expect(isJson('  {"a": 1}  ')).toBe(true);
    });
  });
});
