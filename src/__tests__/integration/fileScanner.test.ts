import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("fileScanner integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("scans and finds file signatures in memory", async () => {
    const matches = [
      { address: "0x10000", fileType: "PNG", module: "app", offset: "0x500" },
      { address: "0x20000", fileType: "JPEG", module: "libgraphics.so", offset: "0x0" },
      { address: "0x30000", fileType: "SQLite", module: null, offset: null },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...matches) }));

    const result = await runUtilityScript("test", "file-scan");
    expect(result.data).toHaveLength(3);
    expect(result.data[0]).toEqual(matches[0]);
    expect(result.data[2]).toEqual(matches[2]);
  });

  it("dumps file from memory in chunks", async () => {
    const chunks = [
      { offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
      { offset: 8, bytes: [0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52] },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...chunks) }));

    const result = await runUtilityScript("test", "dump-file:0x10000");
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(chunks[0]);
    expect(result.data[1]).toEqual(chunks[1]);
  });

  it("handles scan with no results", async () => {
    mockSession = createMockSession(() => createMockScript({ messages: [] }));

    const result = await runUtilityScript("test", "file-scan");
    expect(result.data).toHaveLength(0);
    expect(result.error).toBeUndefined();
  });

  it("handles scan error", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "error", description: "Memory access violation" }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test", "file-scan");
    expect(result.error).toBe("Memory access violation");
  });
});
