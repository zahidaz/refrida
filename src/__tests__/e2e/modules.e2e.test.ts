import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import {
  enumerateModulesScript,
  enumerateExportsScript,
  enumerateImportsScript,
  enumerateRangesScript,
} from "@/lib/utilityScripts.ts";

let device: Device;
let session: Session;
let reachable = false;
let smallModule: string;

beforeAll(async () => {
  reachable = await isServerReachable();
  if (!reachable) return;
  device = await getDevice();
  const proc = await findTestProcess(device);
  session = await device.attach(proc.pid);

  const mods = await runScript<{ name: string; size: number }>(session, enumerateModulesScript());
  const sorted = [...mods.data].sort((a, b) => a.size - b.size);
  smallModule = sorted[Math.min(2, sorted.length - 1)]?.name ?? mods.data[0]?.name;
});

afterAll(async () => {
  if (session) {
    try { await session.detach(); } catch {}
  }
});

describe("modules e2e", () => {
  it("enumerates modules with name, base, size, path", async () => {
    if (!reachable) return;
    const result = await runScript<{ name: string; base: string; size: number; path: string }>(
      session,
      enumerateModulesScript(),
    );
    expect(result.data.length).toBeGreaterThan(0);
    const mod = result.data[0];
    expect(mod).toHaveProperty("name");
    expect(mod).toHaveProperty("base");
    expect(mod).toHaveProperty("size");
    expect(mod).toHaveProperty("path");
    expect(typeof mod.name).toBe("string");
    expect(typeof mod.size).toBe("number");
  });

  it("enumerates exports for a module", async () => {
    if (!reachable || !smallModule) return;
    const result = await runScript<{ type: string; name: string; address: string }>(
      session,
      enumerateExportsScript(smallModule),
    );
    expect(Array.isArray(result.data)).toBe(true);
    if (result.data.length > 0) {
      expect(result.data[0]).toHaveProperty("name");
      expect(result.data[0]).toHaveProperty("address");
    }
  });

  it("enumerates imports for a module", async () => {
    if (!reachable || !smallModule) return;
    const result = await runScript<{ name: string; address: string }>(
      session,
      enumerateImportsScript(smallModule),
    );
    expect(Array.isArray(result.data)).toBe(true);
  });

  it("enumerates memory ranges for a module", async () => {
    if (!reachable || !smallModule) return;
    const result = await runScript<{ base: string; size: number; protection: string }>(
      session,
      enumerateRangesScript(smallModule),
    );
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("base");
    expect(result.data[0]).toHaveProperty("size");
    expect(result.data[0]).toHaveProperty("protection");
  });
});
