import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { startMonitor } from "@/lib/monitorRunner.ts";

describe("startMonitor", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("returns null when no session", async () => {
    const onMessage = vi.fn();
    const onError = vi.fn();
    const handle = await startMonitor("test", onMessage, onError);
    expect(handle).toBeNull();
    expect(onError).toHaveBeenCalledWith("No active session");
  });

  it("calls onMessage for each payload", async () => {
    const received: unknown[] = [];
    const script = createMockScript({
      messages: [
        { type: "send", payload: { event: "connect", fd: 1 } },
        { type: "send", payload: { event: "send", fd: 1 } },
      ],
      autoComplete: false,
    });
    mockSession = createMockSession(() => script);

    const handle = await startMonitor("test", (data) => received.push(data));

    expect(handle).not.toBeNull();
    expect(received).toHaveLength(2);
    expect(received[0]).toEqual({ event: "connect", fd: 1 });
    expect(received[1]).toEqual({ event: "send", fd: 1 });
  });

  it("calls onError for script error", async () => {
    const script = createMockScript({
      messages: [{ type: "error", description: "Script crashed" }],
      autoComplete: false,
    });
    mockSession = createMockSession(() => script);

    const onMessage = vi.fn();
    const onError = vi.fn();
    await startMonitor("test", onMessage, onError);

    expect(onError).toHaveBeenCalledWith("Script crashed");
    expect(onMessage).not.toHaveBeenCalled();
  });

  it("calls onError for __utility_error__", async () => {
    const script = createMockScript({
      messages: [{ type: "send", payload: { type: "__utility_error__", message: "bad input" } }],
      autoComplete: false,
    });
    mockSession = createMockSession(() => script);

    const onMessage = vi.fn();
    const onError = vi.fn();
    await startMonitor("test", onMessage, onError);

    expect(onError).toHaveBeenCalledWith("bad input");
  });

  it("stop() calls script.unload()", async () => {
    const script = createMockScript({ messages: [], autoComplete: false });
    mockSession = createMockSession(() => script);

    const handle = await startMonitor("test", vi.fn());
    expect(handle).not.toBeNull();
    await handle!.stop();
    expect(script.unload).toHaveBeenCalled();
  });
});
