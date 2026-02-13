import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("memory integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("reads memory bytes at address", async () => {
    const readResult = { bytes: [0x48, 0x65, 0x6c, 0x6c, 0x6f], address: "0x1000" };
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(readResult) }));

    const result = await runUtilityScript("test", "memory-read:0x1000");
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toEqual(readResult);
  });

  it("writes memory and returns result", async () => {
    const writeResult = { ok: true, address: "0x1000", count: 5 };
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(writeResult) }));

    const result = await runUtilityScript("test", "memory-write:0x1000");
    expect(result.data[0]).toEqual(writeResult);
  });

  it("handles read error", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "send", payload: { type: "__utility_error__", message: "access violation reading 0xDEAD" } }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test", "memory-read:0xDEAD");
    expect(result.error).toBe("access violation reading 0xDEAD");
  });

  it("handles multiple read chunks", async () => {
    const chunks = [
      { bytes: [0x00, 0x01, 0x02], address: "0x1000" },
      { bytes: [0x03, 0x04, 0x05], address: "0x1003" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...chunks) }));

    const result = await runUtilityScript("test", "memory-read-multi");
    expect(result.data).toHaveLength(2);
  });
});
