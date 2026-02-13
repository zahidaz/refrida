import { getSession } from "@/stores/session.ts";
import type { FridaMessage } from "./frida.ts";

export interface UtilityResult<T = unknown> {
  data: T[];
  error?: string;
}

export async function runUtilityScript<T = unknown>(
  source: string,
): Promise<UtilityResult<T>> {
  const session = getSession();
  if (!session || session.isDetached) {
    return { data: [], error: "No active session" };
  }

  const data: T[] = [];

  try {
    const script = await session.createScript(source);

    const done = new Promise<void>((resolve, reject) => {
      script.message.connect((msg: FridaMessage) => {
        if (msg.type === "error") {
          reject(new Error(msg.description ?? "Script error"));
          return;
        }
        if (msg.type === "send" && msg.payload != null) {
          const payload = msg.payload as Record<string, unknown>;
          if (payload.type === "__done__") {
            resolve();
            return;
          }
          if (payload.type === "__utility_error__") {
            reject(new Error((payload.message as string) ?? "Unknown error"));
            return;
          }
          data.push(msg.payload as T);
        }
      });

      script.destroyed.connect(() => resolve());
    });

    await script.load();
    await done;

    try {
      await script.unload();
    } catch {}

    return { data };
  } catch (err) {
    return { data, error: err instanceof Error ? err.message : String(err) };
  }
}
