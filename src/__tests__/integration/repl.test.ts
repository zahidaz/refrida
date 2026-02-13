import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("repl integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("evaluates expression and returns result", async () => {
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(2) }));

    const result = await runUtilityScript("test", "repl-eval");
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toBe(2);
  });

  it("evaluates string expression", async () => {
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads("arm64") }));

    const result = await runUtilityScript("test", "repl-eval");
    expect(result.data[0]).toBe("arm64");
  });

  it("handles eval error", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "error", description: "ReferenceError: x is not defined" }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test", "repl-eval");
    expect(result.error).toBe("ReferenceError: x is not defined");
  });

  it("handles complex object result", async () => {
    const obj = { pid: 1234, arch: "arm64", platform: "linux" };
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(obj) }));

    const result = await runUtilityScript("test", "repl-eval");
    expect(result.data[0]).toEqual(obj);
  });
});
