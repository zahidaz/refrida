import { useReplStore } from "@/stores/repl.ts";
import { useSessionStore } from "@/stores/session.ts";

export default function ReplInput() {
  const { input, setInput, execute, historyUp, historyDown, running } =
    useReplStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      execute();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      historyUp();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      historyDown();
    }
  }

  return (
    <div
      className="flex items-center gap-1 px-2 py-1 border-t shrink-0"
      style={{
        borderColor: "var(--border)",
        background: "var(--bg-secondary)",
      }}
    >
      <span
        className="text-xs font-mono font-bold shrink-0"
        style={{ color: "var(--accent-text)" }}
      >
        &gt;
      </span>
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        disabled={!sessionActive || running}
        placeholder={sessionActive ? "Evaluate expression..." : "Attach to a process first"}
        className="flex-1 text-xs font-mono bg-transparent outline-none disabled:opacity-40"
        style={{ color: "var(--text-primary)" }}
      />
      {running && (
        <span
          className="text-[10px] shrink-0"
          style={{ color: "var(--text-muted)" }}
        >
          running...
        </span>
      )}
    </div>
  );
}
