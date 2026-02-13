import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import {
  enumerateModulesScript,
  enumerateExportsScript,
  enumerateImportsScript,
  enumerateRangesScript,
} from "@/lib/utilityScripts.ts";

let client: FridaClient;
let session: FridaSession;

beforeAll(async () => {
  if (!(await isServerReachable())) return;
  client = await connectClient();
  const proc = await findTestProcess(client);
  session = await client.attach(proc.pid);
});

afterAll(async () => {
  if (session && !session.isDetached) session.detach();
});

describe("modules e2e", () => {
  it("enumerates modules with name, base, size, path", async () => {
    if (!session) return;
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
    if (!session) return;
    const mods = await runScript<{ name: string }>(session, enumerateModulesScript());
    const firstMod = mods.data[0];
    if (!firstMod) return;

    const result = await runScript<{ type: string; name: string; address: string }>(
      session,
      enumerateExportsScript(firstMod.name),
    );
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("name");
    expect(result.data[0]).toHaveProperty("address");
  });

  it("enumerates imports for a module", async () => {
    if (!session) return;
    const mods = await runScript<{ name: string }>(session, enumerateModulesScript());
    const firstMod = mods.data[0];
    if (!firstMod) return;

    const result = await runScript<{ name: string; address: string }>(
      session,
      enumerateImportsScript(firstMod.name),
    );
    expect(Array.isArray(result.data)).toBe(true);
  });

  it("enumerates memory ranges for a module", async () => {
    if (!session) return;
    const mods = await runScript<{ name: string }>(session, enumerateModulesScript());
    const firstMod = mods.data[0];
    if (!firstMod) return;

    const result = await runScript<{ base: string; size: number; protection: string }>(
      session,
      enumerateRangesScript(firstMod.name),
    );
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("base");
    expect(result.data[0]).toHaveProperty("size");
    expect(result.data[0]).toHaveProperty("protection");
  });
});
