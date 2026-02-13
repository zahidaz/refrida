import { type ConsoleLine as ConsoleLineType, consoleLineColor, isJson } from "@/stores/console.ts";
import { useConsoleStore } from "@/stores/console.ts";
import JsonTree from "./JsonTree.tsx";

interface Props {
  line: ConsoleLineType;
  index: number;
}

export default function ConsoleLine({ line, index }: Props) {
  const { copiedIndex, copyLine } = useConsoleStore();

  const jsonData = isJson(line.text) ? JSON.parse(line.text) : null;

  return (
    <div
      className="flex items-start px-2 py-0.5 text-xs font-mono group hover-row"
      style={{ color: "var(--text-primary)" }}
    >
      <span
        className="flex-shrink-0 select-none mr-2"
        style={{ color: "var(--text-muted)", minWidth: "5.5rem" }}
      >
        {line.timestamp}
      </span>
      <div className="flex-1 min-w-0 break-all select-text" style={{ color: consoleLineColor(line.level) }}>
        {jsonData ? <JsonTree data={jsonData} /> : line.text}
      </div>
      <button
        className="flex-shrink-0 text-[10px] px-1 ml-1 rounded opacity-0 group-hover:opacity-60 hover:!opacity-100 select-none"
        style={{ color: "var(--text-muted)" }}
        onClick={() => copyLine(line, index)}
        title="Copy line"
      >
        {copiedIndex === index ? (
          <i className="fa-solid fa-check" style={{ color: "var(--console-ok)" }} />
        ) : (
          <i className="fa-regular fa-copy" />
        )}
      </button>
    </div>
  );
}
