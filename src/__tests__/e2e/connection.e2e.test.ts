import { describe, it, expect, beforeAll } from "vitest";
import { connectClient, isServerReachable } from "./helpers.ts";
import type { FridaClient } from "@/lib/frida.ts";

let client: FridaClient;

beforeAll(async () => {
  const reachable = await isServerReachable();
  if (!reachable) {
    console.log("Skipping E2E tests: frida-server not reachable");
    return;
  }
  client = await connectClient();
});

describe("connection e2e", () => {
  it("connects and enumerates processes", async () => {
    if (!client) return;
    const processes = await client.enumerateProcesses();
    expect(processes.length).toBeGreaterThan(0);
    expect(processes[0]).toHaveProperty("pid");
    expect(processes[0]).toHaveProperty("name");
  });

  it("queries system parameters", async () => {
    if (!client) return;
    const params = await client.querySystemParameters();
    expect(params).toHaveProperty("os");
    expect(params).toHaveProperty("arch");
  });

  it("enumerates applications", async () => {
    if (!client) return;
    const apps = await client.enumerateApplications();
    expect(Array.isArray(apps)).toBe(true);
  });
});
