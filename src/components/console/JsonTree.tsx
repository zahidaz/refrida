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
    return <span className="text-gray-500">...</span>;
  }

  const isObject = value !== null && typeof value === "object";

  if (!isObject) {
    const valClass =
      typeof value === "string"
        ? "text-green-400"
        : typeof value === "number"
          ? "text-blue-400"
          : typeof value === "boolean"
            ? "text-purple-400"
            : value === null
              ? "text-gray-500"
              : "text-gray-200";
    const display =
      typeof value === "string" ? `"${value}"` : String(value);
    return (
      <span className="json-leaf">
        {label && (
          <span className="text-cyan-300 mr-1">{label}: </span>
        )}
        <span className={valClass}>{display}</span>
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
        className="json-toggle cursor-pointer select-none hover:text-white"
        onClick={() => setCollapsed(!collapsed)}
      >
        <span className="inline-block w-3 text-gray-500 text-[10px] mr-0.5">
          {collapsed ? "\u25B6" : "\u25BC"}
        </span>
        {label && (
          <span className="text-cyan-300 mr-1">{label}: </span>
        )}
        {collapsed && <span className="text-gray-500">{preview}</span>}
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
