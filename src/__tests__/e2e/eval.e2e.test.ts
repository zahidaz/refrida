import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";
import { evalScript } from "@/lib/utilityScripts.ts";

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

describe("eval e2e", () => {
  it("evaluates arithmetic expression", async () => {
    if (!reachable) return;
    const result = await runScript(session, evalScript("return 1 + 1"));
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toBe(2);
  });

  it("evaluates Process.arch", async () => {
    if (!reachable) return;
    const result = await runScript(session, evalScript("return Process.arch"));
    expect(result.data.length).toBeGreaterThan(0);
    const arch = result.data[0] as string;
    expect(["arm", "arm64", "ia32", "x64"]).toContain(arch);
  });

  it("evaluates Process.platform", async () => {
    if (!reachable) return;
    const result = await runScript(session, evalScript("return Process.platform"));
    expect(result.data.length).toBeGreaterThan(0);
    const platform = result.data[0] as string;
    expect(["linux", "darwin", "windows", "freebsd", "qnx"]).toContain(platform);
  });
});
