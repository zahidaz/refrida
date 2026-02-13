import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { startMonitor } from "@/lib/monitorRunner.ts";

describe("monitors integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("receives network events", async () => {
    const events = [
      { type: "send", payload: { event: "__started__" } },
      { type: "send", payload: { event: "connect", fd: 3, ip: "192.168.1.1", port: 443, ts: 1000 } },
      { type: "send", payload: { event: "send", fd: 3, length: 128, ts: 1001 } },
      { type: "send", payload: { event: "recv", fd: 3, length: 256, ts: 1002 } },
      { type: "send", payload: { event: "close", fd: 3, ts: 1003 } },
    ] as Array<{ type: "send"; payload: unknown }>;

    const script = createMockScript({ messages: events, autoComplete: false });
    mockSession = createMockSession(() => script);

    const received: unknown[] = [];
    const handle = await startMonitor("test", (data) => received.push(data));

    expect(handle).not.toBeNull();
    expect(received).toHaveLength(5);
    expect(received[0]).toEqual({ event: "__started__" });
    expect(received[1]).toEqual({ event: "connect", fd: 3, ip: "192.168.1.1", port: 443, ts: 1000 });
  });

  it("receives file events", async () => {
    const events = [
      { type: "send", payload: { event: "__started__" } },
      { type: "send", payload: { event: "open", fd: 5, path: "/etc/hosts", ts: 2000 } },
      { type: "send", payload: { event: "read", fd: 5, length: 64, ts: 2001 } },
      { type: "send", payload: { event: "close", fd: 5, ts: 2002 } },
    ] as Array<{ type: "send"; payload: unknown }>;

    const script = createMockScript({ messages: events, autoComplete: false });
    mockSession = createMockSession(() => script);

    const received: unknown[] = [];
    const handle = await startMonitor("test", (data) => received.push(data));

    expect(handle).not.toBeNull();
    expect(received).toHaveLength(4);
  });

  it("receives stalker trace events", async () => {
    const events = [
      { type: "send", payload: { event: "__started__" } },
      { type: "send", payload: { type: "call", address: "0x1000", target: "0x2000", module: "libc.so", symbol: "malloc", ts: 100 } },
      { type: "send", payload: { type: "ret", address: "0x2000", module: "libc.so", symbol: null, ts: 101 } },
    ] as Array<{ type: "send"; payload: unknown }>;

    const script = createMockScript({ messages: events, autoComplete: false });
    mockSession = createMockSession(() => script);

    const received: unknown[] = [];
    await startMonitor("test", (data) => received.push(data));

    expect(received).toHaveLength(3);
    expect((received[1] as Record<string, unknown>).type).toBe("call");
    expect((received[1] as Record<string, unknown>).symbol).toBe("malloc");
  });

  it("receives interceptor hook events", async () => {
    const events = [
      { type: "send", payload: { event: "__started__" } },
      { type: "send", payload: { event: "enter", target: "0x7100", args: ["0x10", "0x20", "0x30"] } },
      { type: "send", payload: { event: "leave", target: "0x7100", retval: "0x40" } },
    ] as Array<{ type: "send"; payload: unknown }>;

    const script = createMockScript({ messages: events, autoComplete: false });
    mockSession = createMockSession(() => script);

    const received: unknown[] = [];
    await startMonitor("test", (data) => received.push(data));

    expect(received).toHaveLength(3);
    expect((received[1] as Record<string, unknown>).event).toBe("enter");
    expect((received[2] as Record<string, unknown>).event).toBe("leave");
  });
});
