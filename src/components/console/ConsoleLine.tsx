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
      className="flex items-start px-2 py-0.5 text-xs font-mono cursor-pointer group"
      style={{ color: "var(--text-primary)" }}
      onMouseEnter={(e) =>
        (e.currentTarget.style.background = "var(--hover-bg)")
      }
      onMouseLeave={(e) =>
        (e.currentTarget.style.background = "transparent")
      }
      onClick={() => copyLine(line, index)}
    >
      <span
        className="w-20 flex-shrink-0 select-none"
        style={{ color: "var(--text-muted)" }}
      >
        {line.timestamp}
      </span>
      <div className={`flex-1 break-all ${consoleLineClass(line.level)}`}>
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
