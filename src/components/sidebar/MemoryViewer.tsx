import { useState } from "react";
import { useSessionStore } from "@/stores/session.ts";
import { navigateToMemory } from "@/lib/navigation.ts";

export default function MemoryViewer() {
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const [address, setAddress] = useState("");

  if (!sessionActive) {
    return (
      <div
        className="flex-1 flex items-center justify-center text-xs"
        style={{ color: "var(--text-muted)" }}
      >
        Attach to a process to view memory
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-1.5 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <span
          className="text-xs font-semibold"
          style={{ color: "var(--text-primary)" }}
        >
          Memory
        </span>
      </div>

      <div
        className="flex flex-wrap items-center gap-1.5 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <input
          type="text"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && address.trim()) navigateToMemory(address.trim());
          }}
          placeholder="0x7fff..."
          className="text-[11px] font-mono px-2 py-1 rounded border outline-none flex-1 min-w-0"
          style={{
            background: "var(--bg-input)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
          }}
        />
        <button
          onClick={() => {
            if (address.trim()) navigateToMemory(address.trim());
          }}
          disabled={!address.trim()}
          className="text-[10px] px-2 py-1 rounded font-medium text-white disabled:opacity-40"
          style={{ background: "var(--accent)" }}
        >
          Open
        </button>
      </div>

      <div
        className="flex-1 flex items-center justify-center px-6"
        style={{ color: "var(--text-muted)" }}
      >
        <div className="text-center">
          <i
            className="fa-solid fa-memory text-2xl mb-3 block"
            style={{ opacity: 0.3 }}
          />
          <p className="text-xs mb-2">
            Enter a memory address to open a Hex Viewer tab, or click any address in the Module Browser.
          </p>
          <p className="text-[10px]">
            Each hex tab has its own navigation, search, and editing tools.
          </p>
        </div>
      </div>
    </div>
  );
}
