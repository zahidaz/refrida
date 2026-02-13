import Modal from "@/components/ui/Modal.tsx";
import { useLayoutStore } from "@/stores/layout.ts";
import { useConnectionStore } from "@/stores/connection.ts";

interface FlatEntry {
  label: string;
  value: string;
}

function flattenInfo(info: Record<string, unknown>): FlatEntry[] {
  const result: FlatEntry[] = [];
  for (const [key, val] of Object.entries(info)) {
    if (key === "icon" || key === "id") continue;
    if (val === null || val === undefined) continue;
    if (typeof val === "object" && !Array.isArray(val)) {
      const obj = val as Record<string, unknown>;
      for (const [subKey, subVal] of Object.entries(obj)) {
        if (subVal === null || subVal === undefined) continue;
        const flatVal = typeof subVal === "object"
          ? JSON.stringify(subVal)
          : String(subVal);
        result.push({ label: `${key}.${subKey}`, value: flatVal });
      }
    } else if (Array.isArray(val)) {
      result.push({ label: key, value: val.join(", ") });
    } else {
      result.push({ label: key, value: String(val) });
    }
  }
  return result;
}

export default function ServerInfoDialog() {
  const setServerInfoOpen = useLayoutStore((s) => s.setServerInfoOpen);
  const deviceInfo = useConnectionStore((s) => s.deviceInfo);
  const connected = useConnectionStore((s) => s.connected);
  const serverUrl = useConnectionStore((s) => s.serverUrl);

  const entries = deviceInfo ? flattenInfo(deviceInfo) : [];

  return (
    <Modal onClose={() => setServerInfoOpen(false)}>
      <div
        className="rounded-lg border p-5 w-full max-w-[440px] flex flex-col gap-3"
        style={{
          background: "var(--bg-primary)",
          borderColor: "var(--border)",
        }}
      >
        <div className="flex items-center justify-between">
          <span
            className="text-sm font-semibold"
            style={{ color: "var(--text-primary)" }}
          >
            Server Information
          </span>
          <span className="flex items-center gap-1.5 text-xs">
            <span
              className="inline-block w-1.5 h-1.5 rounded-full"
              style={{ background: connected ? "#22c55e" : "#6b7280" }}
            />
            <span style={{ color: connected ? "#22c55e" : "var(--text-muted)" }}>
              {connected ? serverUrl : "Not connected"}
            </span>
          </span>
        </div>

        {entries.length > 0 ? (
          <div
            className="flex flex-col gap-1.5 rounded-md border p-3"
            style={{
              borderColor: "var(--border)",
              background: "var(--bg-secondary)",
            }}
          >
            {entries.map((entry) => (
              <div key={entry.label} className="flex items-start gap-3 text-[11px]">
                <span
                  className="shrink-0 min-w-[100px] text-right font-medium"
                  style={{ color: "var(--text-muted)" }}
                >
                  {entry.label}
                </span>
                <span
                  className="break-all"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {entry.value}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div
            className="text-xs text-center py-4"
            style={{ color: "var(--text-muted)" }}
          >
            {connected ? "No device info available." : "Connect to a frida-server to view device information."}
          </div>
        )}

        <div
          className="text-[10px] flex items-center justify-between"
          style={{ color: "var(--text-muted)" }}
        >
          <span>Minimum supported: frida-server v16.6.0</span>
          <a
            href="https://github.com/frida/frida/releases"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--accent)" }}
          >
            Releases
          </a>
        </div>
      </div>
    </Modal>
  );
}
