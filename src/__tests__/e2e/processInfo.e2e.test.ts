import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import { processInfoScript, enumerateThreadsScript, enumerateEnvVarsScript } from "@/lib/utilityScripts.ts";

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

describe("processInfo e2e", () => {
  it("fetches process details", async () => {
    if (!session) return;
    const result = await runScript<Record<string, unknown>>(session, processInfoScript());
    expect(result.data).toHaveLength(1);
    const info = result.data[0];
    expect(info).toHaveProperty("pid");
    expect(info).toHaveProperty("arch");
    expect(info).toHaveProperty("platform");
    expect(info).toHaveProperty("pointerSize");
    expect(info).toHaveProperty("mainModule");
    expect(typeof info.pid).toBe("number");
  });

  it("enumerates threads", async () => {
    if (!session) return;
    const result = await runScript<{ id: number; state: string }>(session, enumerateThreadsScript());
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("id");
    expect(result.data[0]).toHaveProperty("state");
  });

  it("enumerates environment variables", async () => {
    if (!session) return;
    const result = await runScript<{ key: string; value: string }>(session, enumerateEnvVarsScript());
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("key");
    expect(result.data[0]).toHaveProperty("value");
  });
});
