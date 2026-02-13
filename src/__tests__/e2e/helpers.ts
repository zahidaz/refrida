import type { FridaClient, FridaSession, FridaMessage } from "@/lib/frida.ts";

const FRIDA_HOST = process.env.FRIDA_HOST || "127.0.0.1:27042";

let FridaWeb: typeof import("frida-web-client-browserify");

async function getFridaWeb() {
  if (!FridaWeb) {
    FridaWeb = await import("frida-web-client-browserify");
  }
  return FridaWeb;
}

export async function connectClient(host?: string): Promise<FridaClient> {
  const fw = await getFridaWeb();
  const client = new fw.Client(host || FRIDA_HOST, {
    tls: fw.TransportLayerSecurity.Disabled,
  });
  return client as unknown as FridaClient;
}

export async function isServerReachable(host?: string): Promise<boolean> {
  try {
    const client = await connectClient(host);
    await client.enumerateProcesses();
    return true;
  } catch {
    return false;
  }
}

export async function findTestProcess(client: FridaClient): Promise<{ pid: number; name: string }> {
  const processes = await client.enumerateProcesses();
  const sleep = processes.find((p) => p.name === "sleep");
  if (sleep) return { pid: sleep.pid, name: sleep.name };

  const server = processes.find((p) => p.name.includes("frida-server"));
  if (server) return { pid: server.pid, name: server.name };

  const sorted = [...processes].sort((a, b) => b.pid - a.pid);
  return { pid: sorted[0].pid, name: sorted[0].name };
}

export interface ScriptResult<T = unknown> {
  data: T[];
  error?: string;
}

export async function runScript<T = unknown>(
  session: FridaSession,
  source: string,
  name?: string,
  timeout = 15000,
): Promise<ScriptResult<T>> {
  const data: T[] = [];

  const script = await session.createScript(source, name ? { name } : undefined);

  const done = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Script timeout")), timeout);

    script.message.connect((msg: FridaMessage) => {
      if (msg.type === "error") {
        clearTimeout(timer);
        reject(new Error(msg.description ?? "Script error"));
        return;
      }
      if (msg.type === "send" && msg.payload != null) {
        const payload = msg.payload as Record<string, unknown>;
        if (payload.type === "__done__") {
          clearTimeout(timer);
          resolve();
          return;
        }
        if (payload.type === "__utility_error__") {
          clearTimeout(timer);
          reject(new Error((payload.message as string) ?? "Unknown error"));
          return;
        }
        data.push(msg.payload as T);
      }
    });

    script.destroyed.connect(() => {
      clearTimeout(timer);
      resolve();
    });
  });

  await script.load();
  await done;

  try {
    await script.unload();
  } catch {}

  return { data };
}
