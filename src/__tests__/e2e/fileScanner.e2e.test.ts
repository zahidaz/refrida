import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import { scanFileSignaturesScript } from "@/lib/utilityScripts.ts";

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

describe("fileScanner e2e", () => {
  it("scans for file signatures in memory", async () => {
    if (!session) return;
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
