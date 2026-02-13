import { describe, it, expect, beforeEach } from "vitest";
import { useStalkerStore, getFilteredEvents, type StalkerEvent } from "@/stores/stalker.ts";

const MOCK_EVENTS: StalkerEvent[] = [
  { type: "call", address: "0x1000", module: "libc.so", symbol: "malloc", ts: 1 },
  { type: "call", address: "0x2000", module: "libssl.so", symbol: "SSL_read", ts: 2 },
  { type: "ret", address: "0x1000", module: "libc.so", symbol: "malloc", ts: 3 },
  { type: "call", address: "0x3000", module: null, symbol: null, ts: 4 },
];

describe("stalker store", () => {
  beforeEach(() => {
    useStalkerStore.setState({
      active: false,
      events: MOCK_EVENTS,
      error: null,
      threadId: "",
      eventTypes: { call: true, ret: false, exec: false, block: false, compile: false },
      filterModule: "",
      filterSearch: "",
    });
  });

  describe("getFilteredEvents", () => {
    it("returns all events when no filters", () => {
      const result = getFilteredEvents(useStalkerStore.getState());
      expect(result).toHaveLength(4);
    });

    it("filters by module name", () => {
      useStalkerStore.setState({ filterModule: "libc" });
      const result = getFilteredEvents(useStalkerStore.getState());
      expect(result).toHaveLength(2);
      expect(result.every((e) => e.module === "libc.so")).toBe(true);
    });

    it("filters by search (address)", () => {
      useStalkerStore.setState({ filterSearch: "0x2000" });
      const result = getFilteredEvents(useStalkerStore.getState());
      expect(result).toHaveLength(1);
      expect(result[0].symbol).toBe("SSL_read");
    });

    it("filters by search (symbol)", () => {
      useStalkerStore.setState({ filterSearch: "malloc" });
      const result = getFilteredEvents(useStalkerStore.getState());
      expect(result).toHaveLength(2);
    });

    it("combines module and search filters", () => {
      useStalkerStore.setState({ filterModule: "libc", filterSearch: "0x1000" });
      const result = getFilteredEvents(useStalkerStore.getState());
      expect(result).toHaveLength(2);
    });

    it("excludes events with null module when filtering by module", () => {
      useStalkerStore.setState({ filterModule: "something" });
      const result = getFilteredEvents(useStalkerStore.getState());
      expect(result).toHaveLength(0);
    });
  });

  describe("clear", () => {
    it("empties events", () => {
      useStalkerStore.getState().clear();
      expect(useStalkerStore.getState().events).toHaveLength(0);
    });
  });

  describe("setters", () => {
    it("setThreadId updates threadId", () => {
      useStalkerStore.getState().setThreadId("123");
      expect(useStalkerStore.getState().threadId).toBe("123");
    });

    it("setFilterModule updates filter", () => {
      useStalkerStore.getState().setFilterModule("libc");
      expect(useStalkerStore.getState().filterModule).toBe("libc");
    });
  });
});
