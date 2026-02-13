import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("disasm integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("disassembles instructions at address", async () => {
    const instructions = [
      { address: "0x1000", mnemonic: "mov", opStr: "eax, ebx", size: 2, bytes: [0x89, 0xd8] },
      { address: "0x1002", mnemonic: "ret", opStr: "", size: 1, bytes: [0xc3] },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...instructions) }));

    const result = await runUtilityScript("test", "disasm:0x1000");
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(instructions[0]);
    expect(result.data[1]).toEqual(instructions[1]);
  });

  it("returns error for invalid address", async () => {
    mockSession = createMockSession(() =>
      createMockScript({
        messages: [{ type: "send", payload: { type: "__utility_error__", message: "invalid address" } }],
        autoComplete: false,
      }),
    );

    const result = await runUtilityScript("test", "disasm:0xBAD");
    expect(result.error).toBe("invalid address");
  });

  it("continues disassembly from last instruction", async () => {
    const instructions = [
      { address: "0x1003", mnemonic: "nop", opStr: "", size: 1, bytes: [0x90] },
      { address: "0x1004", mnemonic: "nop", opStr: "", size: 1, bytes: [0x90] },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...instructions) }));

    const result = await runUtilityScript("test", "disasm:0x1003");
    expect(result.data).toHaveLength(2);
  });
});
