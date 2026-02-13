import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import { enumerateModulesScript, readMemoryScript, searchMemoryScript } from "@/lib/utilityScripts.ts";

let device: Device;
let session: Session;
let moduleBase: string;
let reachable = false;

beforeAll(async () => {
  reachable = await isServerReachable();
  if (!reachable) return;
  device = await getDevice();
  const proc = await findTestProcess(device);
  session = await device.attach(proc.pid);

  const mods = await runScript<{ base: string }>(session, enumerateModulesScript());
  if (mods.data[0]) moduleBase = mods.data[0].base;
});

afterAll(async () => {
  if (session) {
    try { await session.detach(); } catch {}
  }
});

describe("memory e2e", () => {
  it("reads memory at a module base address", async () => {
    if (!reachable || !moduleBase) return;
    const result = await runScript<{ bytes: number[]; address: string }>(
      session,
      readMemoryScript(moduleBase, 256),
    );
    expect(result.data).toHaveLength(1);
    expect(result.data[0].bytes.length).toBe(256);
    expect(result.data[0].bytes.every((b: number) => b >= 0 && b <= 255)).toBe(true);
  });

  it("searches memory for a string pattern", async () => {
    if (!reachable) return;
    const result = await runScript<{ address: string; size: number }>(
      session,
      searchMemoryScript("lib", false),
    );
    expect(Array.isArray(result.data)).toBe(true);
  });
});
