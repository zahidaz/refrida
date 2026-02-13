import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("processInfo integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("fetches process info", async () => {
    const info = {
      pid: 1234,
      arch: "arm64",
      platform: "linux",
      pageSize: 4096,
      pointerSize: 8,
      mainModule: { name: "app", base: "0x400000", size: 65536, path: "/data/app" },
      threadCount: 12,
      moduleCount: 45,
      rangeCount: 200,
      totalMappedSize: 16777216,
      currentThreadId: 1234,
    };
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(info) }));

    const result = await runUtilityScript("test", "process-info");
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toEqual(info);
  });

  it("fetches threads", async () => {
    const threads = [
      { id: 1234, state: "running", pc: "0x7000", sp: "0x8000" },
      { id: 1235, state: "waiting", pc: "0x7100", sp: "0x8100" },
      { id: 1236, state: "stopped", pc: null, sp: null },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...threads) }));

    const result = await runUtilityScript("test", "enumerate-threads");
    expect(result.data).toHaveLength(3);
    expect(result.data[0]).toEqual(threads[0]);
    expect(result.data[2]).toEqual(threads[2]);
  });

  it("fetches environment variables", async () => {
    const envVars = [
      { key: "HOME", value: "/root" },
      { key: "PATH", value: "/usr/bin:/bin" },
      { key: "LANG", value: "en_US.UTF-8" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...envVars) }));

    const result = await runUtilityScript("test", "enumerate-env");
    expect(result.data).toHaveLength(3);
    expect(result.data[0]).toEqual(envVars[0]);
  });

  it("handles process info error", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "error", description: "Process terminated" }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test", "process-info");
    expect(result.error).toBe("Process terminated");
  });
});
