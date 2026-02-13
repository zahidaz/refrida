import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import { apiResolverScript } from "@/lib/utilityScripts.ts";

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

describe("search e2e", () => {
  it("resolves API symbols matching a pattern", async () => {
    if (!reachable) return;
    const result = await runScript<{ name: string; address: string }>(
      session,
      apiResolverScript("exports:*!open*"),
    );
    const matches = result.data.filter((d): d is { name: string; address: string } => "name" in d);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]).toHaveProperty("name");
    expect(matches[0]).toHaveProperty("address");
  });
});
