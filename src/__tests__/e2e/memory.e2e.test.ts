import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import { enumerateModulesScript, readMemoryScript, searchMemoryScript } from "@/lib/utilityScripts.ts";

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

describe("memory e2e", () => {
  it("reads memory at a module base address", async () => {
    if (!session || !moduleBase) return;
    const result = await runScript<{ bytes: number[]; address: string }>(
      session,
      readMemoryScript(moduleBase, 256),
    );
    expect(result.data).toHaveLength(1);
    expect(result.data[0].bytes.length).toBe(256);
    expect(result.data[0].bytes.every((b: number) => b >= 0 && b <= 255)).toBe(true);
  });

  it("searches memory for a string pattern", async () => {
    if (!session) return;
    const result = await runScript<{ address: string; size: number }>(
      session,
      searchMemoryScript("lib", false),
    );
    expect(Array.isArray(result.data)).toBe(true);
  });
});
