import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("search integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("finds string matches in memory", async () => {
    const matches = [
      { address: "0x1000", size: 5, context: [72, 101, 108, 108, 111], module: "libc.so" },
      { address: "0x2000", size: 5, context: [72, 101, 108, 108, 111], module: null },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...matches) }));

    const result = await runUtilityScript("test", "memory-search");
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(matches[0]);
  });

  it("finds hex pattern matches", async () => {
    const matches = [{ address: "0x3000", size: 2, context: [0xde, 0xad], module: "app" }];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...matches) }));

    const result = await runUtilityScript("test", "memory-search");
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toEqual(matches[0]);
  });

  it("resolves API symbols", async () => {
    const apiMatches = [
      { name: "libc.so!open", address: "0x7100", module: "libc.so" },
      { name: "libc.so!opendir", address: "0x7200", module: "libc.so" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...apiMatches) }));

    const result = await runUtilityScript("test", "api-resolve");
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(apiMatches[0]);
  });

  it("handles search with no results", async () => {
    mockSession = createMockSession(() => createMockScript({ messages: [] }));

    const result = await runUtilityScript("test", "memory-search");
    expect(result.data).toHaveLength(0);
    expect(result.error).toBeUndefined();
  });
});
