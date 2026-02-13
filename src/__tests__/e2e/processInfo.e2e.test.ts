import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import { processInfoScript, enumerateThreadsScript, enumerateEnvVarsScript } from "@/lib/utilityScripts.ts";

let device: Device;
let session: Session;
let reachable = false;

beforeAll(async () => {
  reachable = await isServerReachable();
  if (!reachable) return;
  device = await getDevice();
  const proc = await findTestProcess(device);
  session = await device.attach(proc.pid);
});

afterAll(async () => {
  if (session) {
    try { await session.detach(); } catch {}
  }
});

describe("processInfo e2e", () => {
  it("fetches process details", async () => {
    if (!reachable) return;
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
    if (!reachable) return;
    const result = await runScript<{ id: number; state: string }>(session, enumerateThreadsScript());
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("id");
    expect(result.data[0]).toHaveProperty("state");
  });

  it("enumerates environment variables", async () => {
    if (!reachable) return;
    const result = await runScript<{ key: string; value: string }>(session, enumerateEnvVarsScript());
    if (result.error) {
      expect(typeof result.error).toBe("string");
      return;
    }
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toHaveProperty("key");
    expect(result.data[0]).toHaveProperty("value");
  });
});
