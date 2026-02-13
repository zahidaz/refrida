import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import { enumerateModulesScript, enumerateExportsScript, disassembleScript } from "@/lib/utilityScripts.ts";

let device: Device;
let session: Session;
let exportAddr: string;
let reachable = false;

beforeAll(async () => {
  reachable = await isServerReachable();
  if (!reachable) return;
  device = await getDevice();
  const proc = await findTestProcess(device);
  session = await device.attach(proc.pid);

  const mods = await runScript<{ name: string }>(session, enumerateModulesScript());
  for (const mod of mods.data) {
    const exps = await runScript<{ type: string; name: string; address: string }>(
      session,
      enumerateExportsScript(mod.name),
    );
    const funcExport = exps.data.find((e) => e.type === "function");
    if (funcExport) {
      exportAddr = funcExport.address;
      break;
    }
  }
});

afterAll(async () => {
  if (session) {
    try { await session.detach(); } catch {}
  }
});

describe("disasm e2e", () => {
  it("disassembles instructions at a function export address", async () => {
    if (!reachable || !exportAddr) return;
    const result = await runScript<{ address: string; mnemonic: string; opStr: string; size: number; bytes: number[] }>(
      session,
      disassembleScript(exportAddr, 10),
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
