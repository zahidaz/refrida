import { useState, useMemo } from "react";
import { useInterceptorStore } from "@/stores/interceptor.ts";
import { useSessionStore } from "@/stores/session.ts";

function Section({ label, children, defaultOpen = true }: { label: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-b" style={{ borderColor: "var(--border)" }}>
      <button
        className="flex items-center gap-1.5 w-full px-3 py-1.5 text-[10px] font-semibold"
        style={{ color: "var(--text-secondary)" }}
        onClick={() => setOpen(!open)}
      >
        <i className={`fa-solid fa-chevron-right text-[7px] transition-transform ${open ? "rotate-90" : ""}`} />
        {label}
      </button>
      {open && <div className="px-3 pb-2 flex flex-col gap-1.5">{children}</div>}
    </div>
  );
}

function SmallInput({ value, onChange, placeholder, disabled, mono }: {
  value: string; onChange: (v: string) => void; placeholder: string; disabled?: boolean; mono?: boolean;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className={`w-full text-[10px] px-2 py-1 rounded border outline-none ${mono ? "font-mono" : ""}`}
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border)",
        color: "var(--text-primary)",
      }}
    />
  );
}

function SmallTextarea({ value, onChange, placeholder, rows = 2 }: {
  value: string; onChange: (v: string) => void; placeholder: string; rows?: number;
}) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      className="w-full text-[10px] px-2 py-1 rounded border outline-none font-mono resize-y"
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border)",
        color: "var(--text-primary)",
      }}
    />
  );
}

function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center gap-1.5 text-[10px] cursor-pointer" style={{ color: "var(--text-secondary)" }}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="w-3 h-3" />
      {label}
    </label>
  );
}

export default function InterceptorPanel() {
  const store = useInterceptorStore();
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const code = useMemo(() => store.generateCode(), [store]);

  if (!sessionActive && store.mode === "live") {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 px-4">
        <i className="fa-solid fa-anchor text-xl" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
        <span className="text-[11px]" style={{ color: "var(--text-muted)" }}>
          Attach to a process to use live hooks
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-2 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <span className="text-xs font-semibold flex-1" style={{ color: "var(--text-primary)" }}>
          Interceptor
        </span>
        <div className="flex gap-0.5 rounded overflow-hidden" style={{ border: "1px solid var(--border)" }}>
          <button
            onClick={() => store.setConfig({ mode: "insert" })}
            className="text-[9px] px-2 py-0.5"
            style={{
              background: store.mode === "insert" ? "var(--accent)" : "transparent",
              color: store.mode === "insert" ? "white" : "var(--text-muted)",
            }}
          >
            Insert
          </button>
          <button
            onClick={() => store.setConfig({ mode: "live" })}
            className="text-[9px] px-2 py-0.5"
            style={{
              background: store.mode === "live" ? "var(--accent)" : "transparent",
              color: store.mode === "live" ? "white" : "var(--text-muted)",
            }}
          >
            Live
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <Section label="Target">
          <div className="flex gap-1.5">
            <button
              onClick={() => store.setTarget({ type: "export" })}
              className="text-[9px] px-2 py-0.5 rounded flex-1"
              style={{
                background: store.target.type === "export" ? "var(--accent-soft)" : "transparent",
                color: store.target.type === "export" ? "var(--accent-text)" : "var(--text-muted)",
                border: "1px solid var(--border)",
              }}
            >
              Export
            </button>
            <button
              onClick={() => store.setTarget({ type: "address" })}
              className="text-[9px] px-2 py-0.5 rounded flex-1"
              style={{
                background: store.target.type === "address" ? "var(--accent-soft)" : "transparent",
                color: store.target.type === "address" ? "var(--accent-text)" : "var(--text-muted)",
                border: "1px solid var(--border)",
              }}
            >
              Address
            </button>
          </div>
          {store.target.type === "export" ? (
            <>
              <SmallInput
                value={store.target.moduleName}
                onChange={(v) => store.setTarget({ moduleName: v })}
                placeholder="Module name (e.g. libc.so)"
              />
              <SmallInput
                value={store.target.exportName}
                onChange={(v) => store.setTarget({ exportName: v })}
                placeholder="Export name (e.g. open)"
              />
            </>
          ) : (
            <SmallInput
              value={store.target.address}
              onChange={(v) => store.setTarget({ address: v })}
              placeholder="Address (e.g. 0x12345678)"
              mono
            />
          )}
        </Section>

        <Section label="Logging">
          <Checkbox
            checked={store.logArgs}
            onChange={(v) => store.setConfig({ logArgs: v })}
            label="Log arguments"
          />
          {store.logArgs && (
            <div className="flex items-center gap-1.5 pl-4">
              <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>Count:</span>
              <input
                type="number"
                min={1}
                max={12}
                value={store.argCount}
                onChange={(e) => store.setConfig({ argCount: Math.max(1, Math.min(12, Number(e.target.value))) })}
                className="w-12 text-[10px] px-1.5 py-0.5 rounded border outline-none text-center"
                style={{ background: "var(--bg-primary)", borderColor: "var(--border)", color: "var(--text-primary)" }}
              />
            </div>
          )}
          <Checkbox
            checked={store.logReturn}
            onChange={(v) => store.setConfig({ logReturn: v })}
            label="Log return value"
          />
          <Checkbox
            checked={store.modifyReturn}
            onChange={(v) => store.setConfig({ modifyReturn: v })}
            label="Modify return value"
          />
          {store.modifyReturn && (
            <SmallInput
              value={store.returnValue}
              onChange={(v) => store.setConfig({ returnValue: v })}
              placeholder="Return value (e.g. 0x1)"
              mono
            />
          )}
        </Section>

        <Section label="Custom Code" defaultOpen={false}>
          <div>
            <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>onEnter(args)</span>
            <SmallTextarea
              value={store.customOnEnter}
              onChange={(v) => store.setConfig({ customOnEnter: v })}
              placeholder="Custom onEnter code..."
            />
          </div>
          <div>
            <span className="text-[9px]" style={{ color: "var(--text-muted)" }}>onLeave(retval)</span>
            <SmallTextarea
              value={store.customOnLeave}
              onChange={(v) => store.setConfig({ customOnLeave: v })}
              placeholder="Custom onLeave code..."
            />
          </div>
        </Section>

        <Section label="Preview">
          <pre
            className="text-[9px] p-2 rounded overflow-x-auto font-mono whitespace-pre"
            style={{
              background: "var(--bg-primary)",
              color: "var(--text-secondary)",
              border: "1px solid var(--border)",
              maxHeight: 200,
            }}
          >
            {code}
          </pre>
        </Section>
      </div>

      <div
        className="px-3 py-2 border-t shrink-0 flex flex-col gap-1.5"
        style={{ borderColor: "var(--border)" }}
      >
        {store.liveError && (
          <div className="text-[9px] px-2 py-1 rounded" style={{ color: "#ef4444", background: "rgba(239, 68, 68, 0.08)" }}>
            {store.liveError}
          </div>
        )}
        {store.mode === "insert" ? (
          <button
            onClick={() => {
              navigator.clipboard.writeText(code);
            }}
            className="w-full text-[10px] px-3 py-1.5 rounded font-medium"
            style={{ color: "white", background: "var(--accent)" }}
          >
            Copy to Clipboard
          </button>
        ) : !store.liveActive ? (
          <button
            onClick={store.startLive}
            disabled={!sessionActive}
            className="w-full text-[10px] px-3 py-1.5 rounded font-medium disabled:opacity-30"
            style={{ color: "white", background: "#22c55e" }}
          >
            Start Hook
          </button>
        ) : (
          <button
            onClick={store.stopLive}
            className="w-full text-[10px] px-3 py-1.5 rounded font-medium"
            style={{ color: "white", background: "#ef4444" }}
          >
            Stop Hook
          </button>
        )}
      </div>
    </div>
  );
}
