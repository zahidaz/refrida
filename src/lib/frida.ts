declare global {
  interface Window {
    FridaWeb: {
      Client: new (host: string, opts?: ClientOptions) => FridaClient;
      TransportLayerSecurity: {
        Disabled: number;
        Enabled: number;
      };
      SessionDetachReason: {
        ApplicationRequested: number;
        ProcessReplaced: number;
        ProcessTerminated: number;
        ConnectionTerminated: number;
        DeviceLost: number;
      };
    };
  }
}

export interface ClientOptions {
  tls?: number | "auto";
  token?: string;
}

export interface FridaProcess {
  pid: number;
  name: string;
  parameters: Record<string, unknown>;
}

export interface FridaApplication {
  identifier: string;
  name: string;
  pid: number;
  parameters: Record<string, unknown>;
}

export interface FridaCrash {
  summary: string;
}

export interface FridaScript {
  message: {
    connect: (handler: (message: FridaMessage) => void) => void;
  };
  destroyed: {
    connect: (handler: () => void) => void;
  };
  logHandler: ((level: string, text: string) => void) | null;
  load: () => Promise<void>;
  unload: () => Promise<void>;
}

export interface FridaSession {
  isDetached: boolean;
  detached: {
    connect: (handler: (reason: number, crash?: FridaCrash) => void) => void;
  };
  detach: () => void;
  createScript: (source: string, opts?: ScriptOptions) => Promise<FridaScript>;
}

export interface FridaClient {
  enumerateProcesses: () => Promise<FridaProcess[]>;
  enumerateApplications: () => Promise<FridaApplication[]>;
  querySystemParameters: () => Promise<Record<string, unknown>>;
  attach: (pid: number) => Promise<FridaSession>;
  spawn: (program: string) => Promise<number>;
  resume: (pid: number) => Promise<void>;
  kill: (pid: number) => Promise<void>;
}

export interface FridaMessage {
  type: "send" | "error";
  payload?: unknown;
  description?: string;
  stack?: string;
}

export interface ScriptOptions {
  name?: string;
  runtime?: string;
}

export const { Client, TransportLayerSecurity, SessionDetachReason } = window.FridaWeb;

export const DETACH_REASONS: Record<number, string> = {
  [SessionDetachReason.ApplicationRequested]: "application requested",
  [SessionDetachReason.ProcessReplaced]: "process replaced",
  [SessionDetachReason.ProcessTerminated]: "process terminated",
  [SessionDetachReason.ConnectionTerminated]: "connection terminated",
  [SessionDetachReason.DeviceLost]: "device lost",
};
