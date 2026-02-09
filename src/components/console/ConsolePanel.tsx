import { useRef, useEffect } from "react";
import { useConsoleStore, getFilteredLines } from "@/stores/console.ts";
import ConsoleToolbar from "./ConsoleToolbar.tsx";
import ConsoleLine from "./ConsoleLine.tsx";

export default function ConsolePanel() {
  const state = useConsoleStore();
  const filtered = getFilteredLines(state);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [state.lines.length]);

  return (
    <div className="flex flex-col h-full">
      <ConsoleToolbar />
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto"
        style={{ background: "var(--bg-primary)" }}
      >
        {filtered.map((line, i) => (
          <ConsoleLine key={i} line={line} index={i} />
        ))}
        {filtered.length === 0 && (
          <div
            className="text-xs px-2 py-4 text-center"
            style={{ color: "var(--text-muted)" }}
          >
            {state.lines.length === 0
              ? "Console output will appear here"
              : "No matching lines"}
          </div>
        )}
      </div>
    </div>
  );
}
