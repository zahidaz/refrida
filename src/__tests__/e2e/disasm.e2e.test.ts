import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import { enumerateModulesScript, disassembleScript } from "@/lib/utilityScripts.ts";

let client: FridaClient;
let session: FridaSession;
let moduleBase: string;

beforeAll(async () => {
  if (!(await isServerReachable())) return;
  client = await connectClient();
  const proc = await findTestProcess(client);
  session = await client.attach(proc.pid);

  const mods = await runScript<{ base: string }>(session, enumerateModulesScript());
  if (mods.data[0]) moduleBase = mods.data[0].base;
});

afterAll(async () => {
  if (session && !session.isDetached) session.detach();
});

describe("disasm e2e", () => {
  it("disassembles instructions at module base", async () => {
    if (!session || !moduleBase) return;
    const result = await runScript<{ address: string; mnemonic: string; opStr: string; size: number; bytes: number[] }>(
      session,
      disassembleScript(moduleBase, 20),
    );
    expect(result.data.length).toBeGreaterThan(0);
    const instr = result.data[0];
    expect(instr).toHaveProperty("address");
    expect(instr).toHaveProperty("mnemonic");
    expect(instr).toHaveProperty("opStr");
    expect(instr).toHaveProperty("size");
    expect(instr).toHaveProperty("bytes");
    expect(typeof instr.mnemonic).toBe("string");
    expect(instr.size).toBeGreaterThan(0);
  });
});
