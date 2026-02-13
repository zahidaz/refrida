import { useState } from "react";

const MAX_DEPTH = 10;

function JsonTreeNode({
  label,
  value,
  depth,
}: {
  label?: string;
  value: unknown;
  depth: number;
}) {
  const [collapsed, setCollapsed] = useState(depth > 0);

  if (depth > MAX_DEPTH) {
    return <span style={{ color: "var(--json-null)" }}>...</span>;
  }

  const isObject = value !== null && typeof value === "object";

  if (!isObject) {
    const color =
      typeof value === "string"
        ? "var(--json-string)"
        : typeof value === "number"
          ? "var(--json-number)"
          : typeof value === "boolean"
            ? "var(--json-bool)"
            : "var(--json-null)";
    const display =
      typeof value === "string" ? `"${value}"` : String(value);
    return (
      <span className="json-leaf">
        {label && (
          <span style={{ color: "var(--json-key)" }} className="mr-1">{label}: </span>
        )}
        <span style={{ color }}>{display}</span>
      </span>
    );
  }

  const isArray = Array.isArray(value);
  const entries = Object.entries(value as Record<string, unknown>);
  const preview = isArray
    ? `[${(value as unknown[]).length}]`
    : `{${entries.length}}`;

  return (
    <div
      className="json-node"
      style={{ paddingLeft: depth > 0 ? "14px" : "0" }}
    >
      <span
        className="json-toggle cursor-pointer select-none"
        role="button"
        tabIndex={0}
        aria-expanded={!collapsed}
        onClick={() => setCollapsed(!collapsed)}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setCollapsed(!collapsed); } }}
      >
        <span
          className="inline-block w-3 text-[10px] mr-0.5"
          style={{ color: "var(--json-collapse)" }}
        >
          {collapsed ? "\u25B6" : "\u25BC"}
        </span>
        {label && (
          <span style={{ color: "var(--json-key)" }} className="mr-1">{label}: </span>
        )}
        {collapsed && <span style={{ color: "var(--json-collapse)" }}>{preview}</span>}
      </span>
      {!collapsed && (
        <div className="json-children">
          {entries.map(([key, val]) => (
            <JsonTreeNode
              key={key}
              label={key}
              value={val}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function JsonTree({ data }: { data: unknown }) {
  return (
    <div className="json-tree text-xs font-mono py-0.5">
      <JsonTreeNode value={data} depth={0} />
    </div>
  );
}
