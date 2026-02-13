import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("runUtilityScript", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("returns error when no session", async () => {
    const result = await runUtilityScript("send('test')");
    expect(result.error).toBe("No active session");
    expect(result.data).toHaveLength(0);
  });

  it("returns error when session is detached", async () => {
    mockSession = { isDetached: true };
    const result = await runUtilityScript("send('test')");
    expect(result.error).toBe("No active session");
  });

  it("collects payloads until __done__", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: sendPayloads({ name: "a" }, { name: "b" }, { name: "c" }),
      }),
    );

    const result = await runUtilityScript<{ name: string }>("test");
    expect(result.data).toHaveLength(3);
    expect(result.data[0].name).toBe("a");
    expect(result.data[1].name).toBe("b");
    expect(result.data[2].name).toBe("c");
    expect(result.error).toBeUndefined();
  });

  it("handles __utility_error__", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "send", payload: { type: "__utility_error__", message: "something broke" } }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test");
    expect(result.error).toBe("something broke");
  });

  it("handles script error message", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "error", description: "ReferenceError: x is not defined" }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test");
    expect(result.error).toBe("ReferenceError: x is not defined");
  });

  it("calls script.unload after completion", async () => {
    const script = createMockScript({ messages: sendPayloads({ ok: true }) });
    mockSession = createMockSession(() => script);

    await runUtilityScript("test");
    expect(script.unload).toHaveBeenCalled();
  });

  it("passes script name to createScript", async () => {
    const session = createMockSession();
    mockSession = session;

    await runUtilityScript("send('hi')", "my-script");
    expect(session.createScript).toHaveBeenCalledWith("send('hi')", { name: "my-script" });
  });
});
