import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connectClient, isServerReachable, findTestProcess, runScript } from "./helpers.ts";
import type { FridaClient, FridaSession } from "@/lib/frida.ts";
import { evalScript } from "@/lib/utilityScripts.ts";

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

describe("eval e2e", () => {
  it("evaluates arithmetic expression", async () => {
    if (!session) return;
    const result = await runScript(session, evalScript("1 + 1"));
    expect(result.data.length).toBeGreaterThan(0);
    expect(result.data[0]).toBe(2);
  });

  it("evaluates Process.arch", async () => {
    if (!session) return;
    const result = await runScript(session, evalScript("Process.arch"));
    expect(result.data.length).toBeGreaterThan(0);
    const arch = result.data[0] as string;
    expect(["arm", "arm64", "ia32", "x64"]).toContain(arch);
  });

  it("evaluates Process.platform", async () => {
    if (!session) return;
    const result = await runScript(session, evalScript("Process.platform"));
    expect(result.data.length).toBeGreaterThan(0);
    const platform = result.data[0] as string;
    expect(["linux", "darwin", "windows", "freebsd", "qnx"]).toContain(platform);
  });
});
