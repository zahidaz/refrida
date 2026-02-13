import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDevice, isServerReachable, findTestProcess, runScript, type Device, type Session } from "./helpers.ts";

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

describe("session e2e", () => {
  it("attaches to a process", () => {
    if (!reachable) return;
    expect(session).toBeDefined();
  });

  it("creates and loads a simple script", async () => {
    if (!reachable) return;
    const result = await runScript(session, `
      send("hello from frida");
      send({ type: "__done__" });
    `);
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toBe("hello from frida");
  });

  it("receives multiple messages", async () => {
    if (!reachable) return;
    const result = await runScript(session, `
      send({ value: 1 });
      send({ value: 2 });
      send({ value: 3 });
      send({ type: "__done__" });
    `);
    expect(result.data).toHaveLength(3);
  });
});
