import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockScript, createMockSession, sendPayloads } from "../helpers/mockSession.ts";

let mockSession: unknown = null;

vi.mock("@/stores/session.ts", () => ({
  getSession: () => mockSession,
  useSessionStore: { getState: () => ({ reset: vi.fn() }), setState: vi.fn() },
}));

import { runUtilityScript } from "@/lib/utilityRunner.ts";

describe("modules integration", () => {
  beforeEach(() => {
    mockSession = null;
  });

  it("enumerates modules", async () => {
    const mods = [
      { name: "libc.so", base: "0x7000", size: 4096, path: "/system/lib/libc.so" },
      { name: "libm.so", base: "0x8000", size: 2048, path: "/system/lib/libm.so" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...mods) }));

    const result = await runUtilityScript(
      'var mods = Process.enumerateModules(); send({ type: "__done__" });',
      "enumerate-modules",
    );
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(mods[0]);
    expect(result.data[1]).toEqual(mods[1]);
    expect(result.error).toBeUndefined();
  });

  it("enumerates exports for a module", async () => {
    const exports = [
      { type: "function", name: "malloc", address: "0x7100" },
      { type: "function", name: "free", address: "0x7200" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...exports) }));

    const result = await runUtilityScript("test", "exports:libc.so");
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(exports[0]);
  });

  it("enumerates imports for a module", async () => {
    const imports = [
      { type: "function", name: "printf", module: "libc.so", address: "0x9000" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...imports) }));

    const result = await runUtilityScript("test", "imports:libm.so");
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toEqual(imports[0]);
  });

  it("enumerates symbols for a module", async () => {
    const symbols = [
      { name: "_start", address: "0x7000", type: "function", isGlobal: true },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...symbols) }));

    const result = await runUtilityScript("test", "symbols:libc.so");
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toEqual(symbols[0]);
  });

  it("enumerates ranges for a module", async () => {
    const ranges = [
      { base: "0x7000", size: 4096, protection: "r-x" },
      { base: "0x8000", size: 2048, protection: "rw-" },
    ];
    mockSession = createMockSession(() => createMockScript({ messages: sendPayloads(...ranges) }));

    const result = await runUtilityScript("test", "sections:libc.so");
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual(ranges[0]);
  });
});
