import { describe, it, expect, beforeAll } from "vitest";
import { getDevice, isServerReachable, type Device } from "./helpers.ts";

let device: Device;
let reachable = false;

beforeAll(async () => {
  reachable = await isServerReachable();
  if (!reachable) return;
  device = await getDevice();
});

describe("connection e2e", () => {
  it("connects and enumerates processes", async () => {
    if (!reachable) return;
    const processes = await device.enumerateProcesses();
    expect(processes.length).toBeGreaterThan(0);
    expect(processes[0]).toHaveProperty("pid");
    expect(processes[0]).toHaveProperty("name");
  });

  it("queries system parameters", async () => {
    if (!reachable) return;
    const params = await device.querySystemParameters();
    expect(params).toHaveProperty("os");
    expect(params).toHaveProperty("arch");
  });

  it("enumerates applications", async () => {
    if (!reachable) return;
    const apps = await device.enumerateApplications();
    expect(Array.isArray(apps)).toBe(true);
  });
});
