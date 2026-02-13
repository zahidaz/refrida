import { getSession } from "@/stores/session.ts";
import type { FridaMessage } from "./frida.ts";

export interface MonitorHandle {
  stop: () => Promise<void>;
}

export async function startMonitor<T = unknown>(
  source: string,
  onMessage: (data: T) => void,
  onError?: (error: string) => void,
): Promise<MonitorHandle | null> {
  const session = getSession();
  if (!session || session.isDetached) {
    onError?.("No active session");
    return null;
  }

  try {
    const script = await session.createScript(source);

    script.message.connect((msg: FridaMessage) => {
      if (msg.type === "error") {
        onError?.(msg.description ?? "Script error");
        return;
      }
      if (msg.type === "send" && msg.payload != null) {
        const payload = msg.payload as Record<string, unknown>;
        if (payload.type === "__utility_error__") {
          onError?.((payload.message as string) ?? "Unknown error");
          return;
        }
        onMessage(msg.payload as T);
      }
    });

    await script.load();

    return {
      stop: async () => {
        try { await script.unload(); } catch {}
      },
    };
  } catch (err) {
    onError?.(err instanceof Error ? err.message : String(err));
    return null;
  }
}
