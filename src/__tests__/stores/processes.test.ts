import { describe, it, expect, beforeEach } from "vitest";
import { useProcessesStore, getFilteredProcesses, getFilteredApplications } from "@/stores/processes.ts";

const MOCK_PROCESSES = [
  { pid: 100, name: "chrome", parameters: {} },
  { pid: 50, name: "safari", parameters: {} },
  { pid: 200, name: "firefox", parameters: {} },
  { pid: 1, name: "launchd", parameters: {} },
];

const MOCK_APPS = [
  { identifier: "com.apple.safari", name: "Safari", pid: 50, parameters: {} },
  { identifier: "com.google.chrome", name: "Chrome", pid: 100, parameters: {} },
  { identifier: "org.mozilla.firefox", name: "Firefox", pid: 0, parameters: {} },
];

describe("processes store", () => {
  beforeEach(() => {
    useProcessesStore.setState({
      processes: MOCK_PROCESSES,
      applications: MOCK_APPS,
      filterText: "",
      sortField: "pid",
      sortAsc: true,
      activeTab: "processes",
      autoRefresh: false,
    });
  });

  describe("getFilteredProcesses", () => {
    it("returns all processes sorted by pid ascending", () => {
      const result = getFilteredProcesses(useProcessesStore.getState());
      expect(result.map((p) => p.pid)).toEqual([1, 50, 100, 200]);
    });

    it("filters by name (case-insensitive)", () => {
      useProcessesStore.setState({ filterText: "chr" });
      const result = getFilteredProcesses(useProcessesStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("chrome");
    });

    it("filters by pid string", () => {
      useProcessesStore.setState({ filterText: "50" });
      const result = getFilteredProcesses(useProcessesStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].pid).toBe(50);
    });

    it("sorts by name ascending", () => {
      useProcessesStore.setState({ sortField: "name", sortAsc: true });
      const result = getFilteredProcesses(useProcessesStore.getState());
      expect(result.map((p) => p.name)).toEqual(["chrome", "firefox", "launchd", "safari"]);
    });

    it("sorts by name descending", () => {
      useProcessesStore.setState({ sortField: "name", sortAsc: false });
      const result = getFilteredProcesses(useProcessesStore.getState());
      expect(result.map((p) => p.name)).toEqual(["safari", "launchd", "firefox", "chrome"]);
    });

    it("sorts by pid descending", () => {
      useProcessesStore.setState({ sortAsc: false });
      const result = getFilteredProcesses(useProcessesStore.getState());
      expect(result.map((p) => p.pid)).toEqual([200, 100, 50, 1]);
    });
  });

  describe("getFilteredApplications", () => {
    it("returns all apps sorted by pid ascending", () => {
      const result = getFilteredApplications(useProcessesStore.getState());
      expect(result.map((a) => a.name)).toEqual(["Firefox", "Safari", "Chrome"]);
    });

    it("filters by name", () => {
      useProcessesStore.setState({ filterText: "safari" });
      const result = getFilteredApplications(useProcessesStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("Safari");
    });

    it("filters by identifier", () => {
      useProcessesStore.setState({ filterText: "mozilla" });
      const result = getFilteredApplications(useProcessesStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].identifier).toBe("org.mozilla.firefox");
    });
  });

  describe("toggleSort", () => {
    it("toggles direction when same field", () => {
      useProcessesStore.getState().toggleSort("pid");
      expect(useProcessesStore.getState().sortAsc).toBe(false);
      useProcessesStore.getState().toggleSort("pid");
      expect(useProcessesStore.getState().sortAsc).toBe(true);
    });

    it("resets to ascending when changing field", () => {
      useProcessesStore.getState().toggleSort("pid");
      useProcessesStore.getState().toggleSort("name");
      expect(useProcessesStore.getState().sortField).toBe("name");
      expect(useProcessesStore.getState().sortAsc).toBe(true);
    });
  });
});
