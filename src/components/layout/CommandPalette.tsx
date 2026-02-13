import { useState, useEffect, useRef, useMemo } from "react";
import { useLayoutStore } from "@/stores/layout.ts";
import { useConnectionStore } from "@/stores/connection.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useConsoleStore } from "@/stores/console.ts";
import { useThemeStore } from "@/stores/theme.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import Modal from "@/components/ui/Modal.tsx";

interface Command {
  id: string;
  label: string;
  shortcut?: string;
  action: () => void;
}

interface Props {
  onRun: () => void;
}

export default function CommandPalette({ onRun }: Props) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const setCommandPaletteOpen = useLayoutStore(
    (s) => s.setCommandPaletteOpen,
  );

  function close() {
    setCommandPaletteOpen(false);
  }

  const commands = useMemo((): Command[] => {
    const connected = useConnectionStore.getState().connected;
    const sessionActive = useSessionStore.getState().sessionActive;
    const scriptActive = useSessionStore.getState().scriptActive;

    const items: Command[] = [
      {
        id: "connect",
        label: connected ? "Disconnect" : "Connect to Server",
        shortcut: "Ctrl+Shift+C",
        action: () => {
          close();
          useLayoutStore.getState().setConnectionDialogOpen(true);
        },
      },
      {
        id: "toggle-theme",
        label: "Toggle Theme",
        action: () => {
          close();
          useThemeStore.getState().toggle();
        },
      },
      {
        id: "toggle-side-panel",
        label: "Toggle Side Panel",
        shortcut: "Ctrl+B",
        action: () => {
          close();
          useLayoutStore.getState().toggleSidePanel();
        },
      },
      {
        id: "toggle-bottom-panel",
        label: "Toggle Console",
        shortcut: "Ctrl+`",
        action: () => {
          close();
          useLayoutStore.getState().toggleBottomPanel();
        },
      },
      {
        id: "clear-console",
        label: "Clear Console",
        shortcut: "Ctrl+Shift+K",
        action: () => {
          close();
          useConsoleStore.getState().clear();
        },
      },
      {
        id: "new-tab",
        label: "New Script Tab",
        action: () => {
          close();
          useScriptsStore.getState().addTab(() => "");
        },
      },
    ];

    if (sessionActive) {
      items.push({
        id: "run-script",
        label: scriptActive ? "Re-run Script" : "Run Script",
        shortcut: "Ctrl+Enter",
        action: () => {
          close();
          onRun();
        },
      });
    }

    if (scriptActive) {
      items.push({
        id: "unload-script",
        label: "Unload Script",
        action: () => {
          close();
          useSessionStore.getState().unloadScript();
        },
      });
    }

    return items;
  }, [onRun]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim();
    if (!q) return commands;
    return commands.filter((c) => c.label.toLowerCase().includes(q));
  }, [query, commands]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && filtered[selectedIndex]) {
      filtered[selectedIndex].action();
    }
  }

  return (
    <Modal onClose={close} align="top"
      className="w-full max-w-[480px] max-h-[60vh] rounded-lg border overflow-hidden"
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border)",
        boxShadow: "0 20px 60px var(--dropdown-shadow)",
      }}
    >
      <input
        ref={inputRef}
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Type a command..."
        className="w-full text-sm px-3 py-2.5 border-b outline-none"
        style={{
          background: "var(--bg-primary)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
      />
      <div className="overflow-y-auto max-h-[calc(60vh-44px)]">
        {filtered.map((cmd, i) => (
          <div
            key={cmd.id}
            className="flex items-center px-3 py-1.5 text-xs cursor-pointer"
            style={{
              color: "var(--text-primary)",
              background:
                i === selectedIndex ? "var(--hover-bg)" : "transparent",
            }}
            onMouseEnter={() => setSelectedIndex(i)}
            onClick={() => cmd.action()}
          >
            <span className="flex-1">{cmd.label}</span>
            {cmd.shortcut && (
              <span
                className="text-[10px] font-mono"
                style={{ color: "var(--text-muted)" }}
              >
                {cmd.shortcut}
              </span>
            )}
          </div>
        ))}
        {filtered.length === 0 && (
          <div
            className="px-3 py-3 text-xs text-center"
            style={{ color: "var(--text-muted)" }}
          >
            No matching commands
          </div>
        )}
      </div>
    </Modal>
  );
}
