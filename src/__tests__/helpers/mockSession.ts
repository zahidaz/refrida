import { vi } from "vitest";
import type { FridaScript, FridaSession, FridaMessage } from "@/lib/frida.ts";

interface MockScriptOptions {
  messages?: Array<{ type: "send"; payload: unknown } | { type: "error"; description: string }>;
  autoComplete?: boolean;
}

export function createMockScript(opts: MockScriptOptions = {}): FridaScript & { _messageHandler: ((msg: FridaMessage) => void) | null } {
  const messages = opts.messages ?? [];
  const autoComplete = opts.autoComplete !== false;
  let messageHandler: ((msg: FridaMessage) => void) | null = null;
  let destroyedHandler: (() => void) | null = null;

  const script: FridaScript & { _messageHandler: ((msg: FridaMessage) => void) | null } = {
    _messageHandler: null,
    message: {
      connect: (h: (msg: FridaMessage) => void) => {
        messageHandler = h;
        script._messageHandler = h;
      },
    },
    destroyed: {
      connect: (h: () => void) => {
        destroyedHandler = h;
      },
    },
    logHandler: null,
    load: vi.fn(async () => {
      for (const msg of messages) {
        messageHandler?.(msg as FridaMessage);
      }
      if (autoComplete) {
        messageHandler?.({ type: "send", payload: { type: "__done__" } });
      }
    }),
    unload: vi.fn(async () => {
      destroyedHandler?.();
    }),
  };

  return script;
}

export function createMockSession(
  scriptFactory?: (source: string, opts?: unknown) => FridaScript,
): FridaSession {
  let detachHandler: ((reason: number) => void) | null = null;

  return {
    isDetached: false,
    detached: {
      connect: (h) => {
        detachHandler = h;
      },
    },
    detach: vi.fn(() => {
      detachHandler?.(0);
    }),
    createScript: vi.fn(async (source: string, opts?: unknown) => {
      if (scriptFactory) return scriptFactory(source, opts);
      return createMockScript();
    }),
  };
}

export function sendPayloads(...payloads: unknown[]) {
  return payloads.map((p) => ({ type: "send" as const, payload: p }));
}
