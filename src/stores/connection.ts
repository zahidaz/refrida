import { create } from "zustand";
import {
  Client,
  TransportLayerSecurity,
  type FridaClient,
  type FridaProcess,
} from "@/lib/frida.ts";
import { getItem, setItem } from "@/lib/storage.ts";
import { useConsoleStore } from "./console.ts";
import { addToHistory } from "@/components/sidebar/SettingsPanel.tsx";
import { useSessionStore } from "./session.ts";
import { useProcessesStore } from "./processes.ts";

interface ConnectionSettings {
  serverUrl: string;
  tls: string;
  token: string;
}

interface ConnectionState {
  serverUrl: string;
  tls: string;
  authToken: string;
  connected: boolean;
  busy: boolean;
  deviceInfo: Record<string, unknown> | null;
  spawnTarget: string;
  setServerUrl: (url: string) => void;
  setTls: (tls: string) => void;
  setAuthToken: (token: string) => void;
  setSpawnTarget: (target: string) => void;
  connect: () => Promise<FridaProcess[] | null>;
  disconnect: () => void;
  spawnProcess: () => Promise<number | null>;
  resumeProcess: (pid: number) => Promise<void>;
  getClient: () => FridaClient | null;
}

let client: FridaClient | null = null;

function readUrlParams() {
  const params = new URLSearchParams(window.location.search);
  return {
    host: params.get("host"),
    tls: params.get("tls"),
    token: params.get("token"),
  };
}

function syncUrlParams(host: string, tls: string, token: string) {
  const params = new URLSearchParams();
  if (host && host !== "127.0.0.1:27042") params.set("host", host);
  if (tls && tls !== "disabled") params.set("tls", tls);
  if (token) params.set("token", token);
  const qs = params.toString();
  const url = qs
    ? `${window.location.pathname}?${qs}`
    : window.location.pathname;
  window.history.replaceState(null, "", url);
}

export const useConnectionStore = create<ConnectionState>((set, get) => {
  const saved = getItem<ConnectionSettings>("refrida-settings", {
    serverUrl: "127.0.0.1:27042",
    tls: "disabled",
    token: "",
  });

  const urlParams = readUrlParams();
  const initialHost = urlParams.host || saved.serverUrl;
  const initialTls = urlParams.tls || saved.tls;
  const initialToken = urlParams.token || saved.token;

  syncUrlParams(initialHost, initialTls, initialToken);

  return {
    serverUrl: initialHost,
    tls: initialTls,
    authToken: initialToken,
    connected: false,
    busy: false,
    deviceInfo: null,
    spawnTarget: "",

    setServerUrl: (serverUrl) => {
      set({ serverUrl });
      syncUrlParams(serverUrl, get().tls, get().authToken);
    },
    setTls: (tls) => {
      set({ tls });
      syncUrlParams(get().serverUrl, tls, get().authToken);
    },
    setAuthToken: (authToken) => {
      set({ authToken });
      syncUrlParams(get().serverUrl, get().tls, authToken);
    },
    setSpawnTarget: (spawnTarget) => set({ spawnTarget }),

    getClient: () => client,

    connect: async () => {
      const { serverUrl, tls, authToken, busy } = get();
      if (busy) return null;
      const host = serverUrl.trim();
      if (!host) return null;
      const append = useConsoleStore.getState().append;

      setItem("refrida-settings", {
        serverUrl: host,
        tls,
        token: authToken.trim(),
      });
      syncUrlParams(host, tls, authToken.trim());

      append(`Connecting to ${host}...`, "system");
      set({ busy: true });

      try {
        const tlsMap: Record<string, number | "auto"> = {
          disabled: TransportLayerSecurity.Disabled,
          enabled: TransportLayerSecurity.Enabled,
          auto: "auto",
        };
        const opts: { tls: number | "auto"; token?: string } = {
          tls: tlsMap[tls] || TransportLayerSecurity.Disabled,
        };
        const token = authToken.trim();
        if (token) opts.token = token;
        client = new Client(host, opts);

        try {
          const params = await client.querySystemParameters();
          set({ deviceInfo: params });
          const os = params.os as Record<string, unknown> | undefined;
          const osName = os?.name ?? os?.id ?? params.platform ?? "";
          const rawVersion = os?.version;
          const osVersion = typeof rawVersion === "string" ? rawVersion : "";
          const arch = typeof params.arch === "string" ? params.arch : "";
          const parts = [osName, osVersion, arch].filter(Boolean);
          if (parts.length > 0) {
            append(`Device: ${parts.join(" ")}`, "system");
          }
          const fridaVersion = params.frida as string | undefined;
          if (fridaVersion) {
            append(`Frida server: v${fridaVersion}`, "system");
            const [major, minor] = fridaVersion.split(".").map(Number);
            if (major < 16 || (major === 16 && minor < 6)) {
              append(
                `Warning: reFrida requires frida-server >= 16.6.0 (found ${fridaVersion}). Some features may not work.`,
                "error",
              );
            }
          }
        } catch {}

        const processes = await client.enumerateProcesses();
        set({ connected: true });
        addToHistory(host, tls);
        append(
          `Connected. ${processes.length} processes found.`,
          "system",
        );
        return processes;
      } catch (err) {
        append(
          `Connection failed: ${(err as Error).message}`,
          "error",
        );
        client = null;
        return null;
      } finally {
        set({ busy: false });
      }
    },

    disconnect: () => {
      useSessionStore.getState().reset();
      useProcessesStore.getState().reset();
      client = null;
      set({ connected: false, deviceInfo: null, spawnTarget: "" });
      useConsoleStore.getState().append("Disconnected.", "system");
    },

    spawnProcess: async () => {
      const { spawnTarget } = get();
      const target = spawnTarget.trim();
      if (!target || !client) return null;
      const append = useConsoleStore.getState().append;
      append(`Spawning ${target}...`, "system");
      try {
        const pid = await client.spawn(target);
        append(`Spawned ${target} with PID ${pid}`, "system");
        return pid;
      } catch (err) {
        append(`Spawn failed: ${(err as Error).message}`, "error");
        return null;
      }
    },

    resumeProcess: async (pid) => {
      if (!client) return;
      const append = useConsoleStore.getState().append;
      try {
        await client.resume(pid);
        append(`Resumed PID ${pid}`, "system");
      } catch (err) {
        append(`Resume failed: ${(err as Error).message}`, "error");
      }
    },
  };
});
