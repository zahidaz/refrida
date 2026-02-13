import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import { scanFileSignaturesScript } from "@/lib/utilityScripts.ts";

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

describe("fileScanner e2e", () => {
  it("scans for file signatures in memory", async () => {
    if (!reachable) return;
    const result = await runScript<{ address: string; fileType: string; module: string | null }>(
      session,
      scanFileSignaturesScript(),
    );
    expect(Array.isArray(result.data)).toBe(true);
    if (result.data.length > 0) {
      expect(result.data[0]).toHaveProperty("address");
      expect(result.data[0]).toHaveProperty("fileType");
    }
  });
});
