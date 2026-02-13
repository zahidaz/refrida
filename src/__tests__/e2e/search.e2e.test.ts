import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import { apiResolverScript } from "@/lib/utilityScripts.ts";

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

describe("search e2e", () => {
  it("resolves API symbols matching a pattern", async () => {
    if (!session) return;
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
