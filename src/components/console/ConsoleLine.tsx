import { type ConsoleLine as ConsoleLineType, consoleLineClass, isJson } from "@/stores/console.ts";
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
      className="flex items-start px-2 py-0.5 text-xs font-mono cursor-pointer group hover-row"
      style={{ color: "var(--text-primary)" }}
      onClick={() => copyLine(line, index)}
    >
      <span
        className="flex-shrink-0 select-none mr-2"
        style={{ color: "var(--text-muted)", minWidth: "5.5rem" }}
      >
        {line.timestamp}
      </span>
      <div className={`flex-1 min-w-0 break-all ${consoleLineClass(line.level)}`}>
        {jsonData ? <JsonTree data={jsonData} /> : line.text}
      </div>
      {copiedIndex === index && (
        <span className="text-[10px] text-green-500 ml-1 select-none">
          Copied!
        </span>
      )}
    </div>
  );
}
