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

export default function DeviceBadges({ info }: { info: Record<string, unknown> }) {
  const parts: string[] = [];
  const osVal = resolveDisplayValue(info.os);
  if (osVal) parts.push(osVal);
  const archVal = resolveDisplayValue(info.arch);
  if (archVal) parts.push(archVal);
  const nameVal = resolveDisplayValue(info.name);
  if (nameVal) parts.push(nameVal);

  if (parts.length === 0) return null;

  return (
    <div className="flex items-center gap-1">
      {parts.map((p, i) => (
        <span key={i} className="device-badge">
          {p}
        </span>
      ))}
    </div>
  );
}
