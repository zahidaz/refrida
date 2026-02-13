import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";

let client: FridaClient;
let session: FridaSession;
let testProcess: { pid: number; name: string };

beforeAll(async () => {
  if (!(await isServerReachable())) return;
  client = await connectClient();
  testProcess = await findTestProcess(client);
  session = await client.attach(testProcess.pid);
});

afterAll(async () => {
  if (session && !session.isDetached) {
    session.detach();
  }
});

describe("session e2e", () => {
  it("attaches to a process", () => {
    if (!session) return;
    expect(session).toBeDefined();
    expect(session.isDetached).toBe(false);
  });

  it("creates and loads a simple script", async () => {
    if (!session) return;
    const result = await runScript(session, `
      send("hello from frida");
      send({ type: "__done__" });
    `);
    expect(result.data).toHaveLength(1);
    expect(result.data[0]).toBe("hello from frida");
  });

  it("receives multiple messages", async () => {
    if (!session) return;
    const result = await runScript(session, `
      send({ value: 1 });
      send({ value: 2 });
      send({ value: 3 });
      send({ type: "__done__" });
    `);
    expect(result.data).toHaveLength(3);
  });
});
