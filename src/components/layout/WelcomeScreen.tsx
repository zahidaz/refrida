import { useLayoutStore } from "@/stores/layout.ts";
import { useConnectionStore } from "@/stores/connection.ts";
import { TEMPLATES } from "@/lib/templates.ts";
import { useIsMobile } from "@/hooks/useIsMobile.ts";

interface Props {
  onLoadScript: (name: string, code: string) => void;
}

const QUICK_START_STEPS = [
  {
    step: "1",
    title: "Start frida-server",
    desc: "Run frida-server on your target device with network listening enabled.",
    code: "frida-server --listen=0.0.0.0:27042",
  },
  {
    step: "2",
    title: "Connect",
    desc: "Click the Connect button in the title bar and enter the server address.",
  },
  {
    step: "3",
    title: "Attach to a process",
    desc: "Browse the process list, pick your target, and attach.",
  },
  {
    step: "4",
    title: "Run a script",
    desc: "Write or pick a template, then hit Run. Output appears in the console below.",
  },
];

const FEATURED_TEMPLATES = ["hello", "modules", "hook-func", "intercept", "stalker", "rpc"];

const SHORTCUTS = [
  { keys: "Ctrl+Enter", action: "Run script" },
  { keys: "Ctrl+P", action: "Command palette" },
  { keys: "Ctrl+B", action: "Toggle sidebar" },
  { keys: "Ctrl+`", action: "Toggle console" },
  { keys: "Ctrl+S", action: "Save to library" },
  { keys: "Ctrl+O", action: "Open file" },
];

export default function WelcomeScreen({ onLoadScript }: Props) {
  const setConnectionDialogOpen = useLayoutStore((s) => s.setConnectionDialogOpen);
  const connected = useConnectionStore((s) => s.connected);
  const isMobile = useIsMobile();

  function loadTemplate(key: string) {
    const t = TEMPLATES[key];
    if (t) {
      onLoadScript(t.label, t.code);
    }
  }

  return (
    <div
      className={`h-full overflow-y-auto py-10 ${isMobile ? "px-4" : "px-8"}`}
      style={{ background: "var(--bg-primary)" }}
    >
      <div className="max-w-2xl mx-auto">
        <div className="mb-8">
          <h1
            className="text-3xl font-bold tracking-tight mb-1"
            style={{ color: "var(--accent)" }}
          >
            reFrida
          </h1>
          <p
            className="text-sm"
            style={{ color: "var(--text-secondary)" }}
          >
            Browser-based IDE for Frida. Connect to a frida-server, attach to
            processes, and run instrumentation scripts.
          </p>
        </div>

        {!connected && (
          <div
            className="rounded-lg border p-4 mb-8 flex items-center justify-between"
            style={{
              background: "var(--bg-secondary)",
              borderColor: "var(--accent)",
              borderStyle: "dashed",
            }}
          >
            <div>
              <p
                className="text-sm font-medium"
                style={{ color: "var(--text-primary)" }}
              >
                Not connected
              </p>
              <p
                className="text-xs mt-0.5"
                style={{ color: "var(--text-muted)" }}
              >
                Connect to a frida-server to get started.
              </p>
            </div>
            <button
              onClick={() => setConnectionDialogOpen(true)}
              className="px-4 py-1.5 rounded text-xs font-medium"
              style={{
                background: "var(--accent)",
                color: "var(--bg-primary)",
              }}
            >
              Connect
            </button>
          </div>
        )}

        <div className="mb-8">
          <h2
            className="text-xs font-semibold uppercase tracking-wide mb-3"
            style={{ color: "var(--text-muted)" }}
          >
            Quick Start
          </h2>
          <div className={`grid ${isMobile ? "grid-cols-1" : "grid-cols-2"} gap-3`}>
            {QUICK_START_STEPS.map((s) => (
              <div
                key={s.step}
                className="rounded-lg border p-3"
                style={{
                  background: "var(--bg-secondary)",
                  borderColor: "var(--border)",
                }}
              >
                <div className="flex items-start gap-2.5">
                  <span
                    className="text-xs font-bold w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5"
                    style={{
                      background: "var(--accent)",
                      color: "var(--bg-primary)",
                    }}
                  >
                    {s.step}
                  </span>
                  <div>
                    <p
                      className="text-xs font-medium"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {s.title}
                    </p>
                    <p
                      className="text-[11px] mt-0.5 leading-relaxed"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {s.desc}
                    </p>
                    {s.code && (
                      <code
                        className="text-[10px] mt-1.5 block px-2 py-1 rounded"
                        style={{
                          background: "var(--bg-primary)",
                          color: "var(--accent)",
                        }}
                      >
                        {s.code}
                      </code>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="mb-8">
          <h2
            className="text-xs font-semibold uppercase tracking-wide mb-3"
            style={{ color: "var(--text-muted)" }}
          >
            Templates
          </h2>
          <div className={`grid ${isMobile ? "grid-cols-2" : "grid-cols-3"} gap-2`}>
            {FEATURED_TEMPLATES.map((key) => {
              const t = TEMPLATES[key];
              if (!t) return null;
              return (
                <button
                  key={key}
                  onClick={() => loadTemplate(key)}
                  className="hover-row text-left rounded-lg border p-2.5 transition-colors"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--bg-secondary)",
                  }}
                >
                  <p
                    className="text-xs font-medium"
                    style={{ color: "var(--text-primary)" }}
                  >
                    {t.label}
                  </p>
                  <p
                    className="text-[10px] mt-0.5 truncate"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {t.code.split("\n")[0]}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        <div>
          <h2
            className="text-xs font-semibold uppercase tracking-wide mb-3"
            style={{ color: "var(--text-muted)" }}
          >
            Keyboard Shortcuts
          </h2>
          <div
            className="rounded-lg border overflow-hidden"
            style={{
              borderColor: "var(--border)",
            }}
          >
            {SHORTCUTS.map((s, i) => (
              <div
                key={s.keys}
                className="flex items-center justify-between px-3 py-1.5"
                style={{
                  background: i % 2 === 0 ? "var(--bg-secondary)" : "var(--bg-primary)",
                }}
              >
                <span
                  className="text-xs"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {s.action}
                </span>
                <kbd
                  className="text-[10px] px-1.5 py-0.5 rounded border"
                  style={{
                    background: "var(--bg-primary)",
                    borderColor: "var(--border)",
                    color: "var(--text-muted)",
                  }}
                >
                  {s.keys}
                </kbd>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
