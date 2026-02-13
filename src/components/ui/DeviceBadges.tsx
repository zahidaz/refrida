import { useState, useRef, useEffect } from "react";

function resolveDisplayValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.name === "string") return obj.name;
    if (typeof obj.id === "string") return obj.id;
    const vals = Object.values(obj).filter((v) => typeof v === "string");
    if (vals.length > 0) return vals[0] as string;
  }
  return "";
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const parts = Object.entries(obj)
      .map(([k, v]) => `${k}: ${v}`)
      .join(", ");
    return parts || "—";
  }
  return String(value);
}

export default function DeviceBadges({ info }: { info: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const parts: string[] = [];
  const osVal = resolveDisplayValue(info.os);
  if (osVal) parts.push(osVal);
  const archVal = resolveDisplayValue(info.arch);
  if (archVal) parts.push(archVal);
  const nameVal = resolveDisplayValue(info.name);
  if (nameVal) parts.push(nameVal);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  if (parts.length === 0) return null;

  const entries = Object.entries(info).filter(
    ([k]) => !["icon", "id"].includes(k),
  );

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 cursor-pointer bg-transparent border-none p-0"
        title="Click for server details"
      >
        {parts.map((p, i) => (
          <span key={i} className="device-badge">
            {p}
          </span>
        ))}
        <i
          className="fa-solid fa-circle-info"
          style={{ fontSize: 9, color: "var(--text-muted)", marginLeft: 2 }}
        />
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-1 rounded-lg border shadow-lg p-3 z-[100] min-w-[260px] max-w-[360px]"
          style={{
            background: "var(--bg-primary)",
            borderColor: "var(--border)",
          }}
        >
          <div
            className="text-[11px] font-semibold mb-2 pb-1 border-b"
            style={{ color: "var(--text-primary)", borderColor: "var(--border)" }}
          >
            Server Information
          </div>
          <div className="flex flex-col gap-1">
            {entries.map(([key, value]) => (
              <div key={key} className="flex items-start gap-2 text-[11px]">
                <span
                  className="shrink-0 w-20 text-right"
                  style={{ color: "var(--text-muted)" }}
                >
                  {key}
                </span>
                <span
                  className="break-all"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {formatValue(value)}
                </span>
              </div>
            ))}
          </div>
          {"frida" in info && (
            <div
              className="text-[10px] mt-2 pt-1 border-t"
              style={{ color: "var(--text-muted)", borderColor: "var(--border)" }}
            >
              Minimum required: v16.6.0
            </div>
          )}
        </div>
      )}
    </div>
  );
}
