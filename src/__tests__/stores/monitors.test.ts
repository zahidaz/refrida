import { describe, it, expect, beforeEach } from "vitest";
import { useMonitorsStore } from "@/stores/monitors.ts";

describe("monitors store", () => {
  beforeEach(() => {
    useMonitorsStore.setState({
      networkActive: false,
      networkEvents: [],
      networkError: null,
      fileActive: false,
      fileEvents: [],
      fileError: null,
      activeTab: "network",
    });
  });

  describe("setActiveTab", () => {
    it("switches to files tab", () => {
      useMonitorsStore.getState().setActiveTab("files");
      expect(useMonitorsStore.getState().activeTab).toBe("files");
    });

    it("switches to network tab", () => {
      useMonitorsStore.setState({ activeTab: "files" });
      useMonitorsStore.getState().setActiveTab("network");
      expect(useMonitorsStore.getState().activeTab).toBe("network");
    });
  });

  describe("clearNetwork", () => {
    it("empties network events", () => {
      useMonitorsStore.setState({
        networkEvents: [
          { event: "connect", fd: 1, ip: "1.2.3.4", port: 443, ts: 1 },
          { event: "send", fd: 1, length: 100, ts: 2 },
        ],
      });
      useMonitorsStore.getState().clearNetwork();
      expect(useMonitorsStore.getState().networkEvents).toHaveLength(0);
    });
  });

  describe("clearFile", () => {
    it("empties file events", () => {
      useMonitorsStore.setState({
        fileEvents: [
          { event: "open", fd: 3, path: "/etc/passwd", ts: 1 },
        ],
      });
      useMonitorsStore.getState().clearFile();
      expect(useMonitorsStore.getState().fileEvents).toHaveLength(0);
    });
  });
});
