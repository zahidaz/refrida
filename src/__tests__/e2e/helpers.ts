import frida from "frida";
import type { Device, Session, Script, Message, SendMessage, ErrorMessage } from "frida";

const FRIDA_HOST = process.env["FRIDA_HOST"] || "127.0.0.1:27042";

let cachedDevice: Device | null = null;

export async function getDevice(host?: string): Promise<Device> {
  if (cachedDevice) return cachedDevice;
  const mgr = frida.getDeviceManager();
  cachedDevice = await mgr.addRemoteDevice(host || FRIDA_HOST);
  return cachedDevice;
}

export async function isServerReachable(host?: string): Promise<boolean> {
  try {
    const device = await getDevice(host);
    await device.enumerateProcesses();
    return true;
  } catch {
    return false;
  }
}

export async function findTestProcess(device: Device): Promise<{ pid: number; name: string }> {
  const processes = await device.enumerateProcesses();
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
  session: Session,
  source: string,
  timeout = 15000,
): Promise<ScriptResult<T>> {
  const data: T[] = [];
  let error: string | undefined;
  const script: Script = await session.createScript(source);
  let settled = false;

  const done = new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        error = "Script timeout";
        resolve();
      }
    }, timeout);

    script.message.connect((message: Message) => {
      if (settled) return;
      if (message.type === "error") {
        settled = true;
        clearTimeout(timer);
        error = (message as ErrorMessage).description ?? "Script error";
        resolve();
        return;
      }
      if (message.type === "send") {
        const payload = (message as SendMessage).payload;
        if (payload != null) {
          const p = payload as Record<string, unknown>;
          if (p.type === "__done__") {
            settled = true;
            clearTimeout(timer);
            resolve();
            return;
          }
          if (p.type === "__utility_error__") {
            settled = true;
            clearTimeout(timer);
            error = (p.message as string) ?? "Unknown error";
            resolve();
            return;
          }
          data.push(payload as T);
        }
      }
    });

    script.destroyed.connect(() => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve();
      }
    });
  });

  await script.load();
  await done;

  try {
    await script.unload();
  } catch {}

  if (error) return { data, error };
  return { data };
}

export type { Device, Session };
