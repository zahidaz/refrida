import { useEffect, useMemo } from "react";
import { useDisasmStore, type AsmTabState, type Instruction } from "@/stores/disasm.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { useBookmarksStore } from "@/stores/bookmarks.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";
import { navigateToMemory, navigateToDisasm } from "@/lib/navigation.ts";

const COUNT_OPTIONS = [50, 100, 200, 500];

const JUMP_MNEMONICS = new Set([
  "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae",
  "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz",
  "b", "bl", "bx", "beq", "bne", "bgt", "blt", "bge", "ble", "bhi", "bls",
  "bcc", "bcs", "cbz", "cbnz", "tbz", "tbnz",
]);
const CALL_MNEMONICS = new Set(["call", "bl", "blr", "blx"]);
const RET_MNEMONICS = new Set(["ret", "retn", "retf"]);
const NOP_MNEMONICS = new Set(["nop"]);

function getMnemonicColor(mnemonic: string): string {
  const m = mnemonic.toLowerCase();
  if (CALL_MNEMONICS.has(m)) return "#60a5fa";
  if (JUMP_MNEMONICS.has(m)) return "#f59e0b";
  if (RET_MNEMONICS.has(m)) return "#ef4444";
  if (NOP_MNEMONICS.has(m)) return "var(--text-muted)";
  if (m.startsWith("push") || m.startsWith("pop")) return "#a78bfa";
  if (m.startsWith("mov") || m.startsWith("ldr") || m.startsWith("str") || m.startsWith("lea")) return "#34d399";
  return "var(--text-primary)";
}

function extractAddress(opStr: string): string | null {
  const match = opStr.match(/0x[0-9a-fA-F]+/);
  return match ? match[0] : null;
}

interface Props {
  tabId: string;
}

function AsmListing({
  instructions,
  selectedIndex,
  onSelect,
}: {
  instructions: Instruction[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
}) {
  const maxAddrLen = useMemo(() => {
    let max = 8;
    for (const insn of instructions) {
      const len = insn.address.length;
      if (len > max) max = len;
    }
    return max;
  }, [instructions]);

  return (
    <div className="font-mono text-[11px] leading-5 select-text">
      <div
        className="flex px-3 py-0.5 border-b sticky top-0"
        style={{
          background: "var(--bg-secondary)",
          borderColor: "var(--border)",
          color: "var(--text-muted)",
        }}
      >
        <span className="shrink-0" style={{ width: maxAddrLen * 7.2 + 8 }}>Address</span>
        <span className="shrink-0" style={{ width: 110 }}>Bytes</span>
        <span className="shrink-0" style={{ width: 80 }}>Mnemonic</span>
        <span>Operands</span>
      </div>
      {instructions.map((insn, i) => {
        const isSelected = selectedIndex === i;
        const bytesStr = insn.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
        const targetAddr = extractAddress(insn.opStr);
        const isJump = JUMP_MNEMONICS.has(insn.mnemonic.toLowerCase());
        const isCall = CALL_MNEMONICS.has(insn.mnemonic.toLowerCase());

        return (
          <div
            key={insn.address}
            className="flex px-3 hover-row cursor-pointer"
            style={{
              background: isSelected ? "var(--accent-soft)" : "transparent",
            }}
            onClick={() => onSelect(i)}
          >
            <span
              className="shrink-0 cursor-pointer"
              style={{ width: maxAddrLen * 7.2 + 8, color: "var(--text-muted)" }}
              onClick={(e) => { e.stopPropagation(); copyToClipboard(insn.address); }}
              title="Copy address"
            >
              {insn.address}
            </span>
            <span
              className="shrink-0 truncate"
              style={{ width: 110, color: "var(--text-muted)" }}
            >
              {bytesStr}
            </span>
            <span
              className="shrink-0 font-semibold"
              style={{ width: 80, color: getMnemonicColor(insn.mnemonic) }}
            >
              {insn.mnemonic}
            </span>
            <span style={{ color: "var(--text-secondary)" }}>
              {targetAddr && (isJump || isCall) ? (
                <>
                  {insn.opStr.slice(0, insn.opStr.indexOf(targetAddr))}
                  <span
                    className="underline cursor-pointer"
                    style={{ color: isCall ? "#60a5fa" : "#f59e0b" }}
                    onClick={(e) => {
                      e.stopPropagation();
                      navigateToDisasm(targetAddr);
                    }}
                    title={`Go to ${targetAddr}`}
                  >
                    {targetAddr}
                  </span>
                  {insn.opStr.slice(insn.opStr.indexOf(targetAddr) + targetAddr.length)}
                </>
              ) : (
                insn.opStr
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function AsmWelcome({ tabId }: { tabId: string }) {
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const tab = useScriptsStore((s) => s.tabs.find((t) => t.id === tabId));
  const store = useDisasmStore();

  useEffect(() => {
    if (sessionActive && tab?.address) {
      store.setAddress(tabId, tab.address);
      store.disassembleAt(tabId, tab.address);
    }
  }, [sessionActive, tab?.address]);

  return (
    <div
      className="flex-1 flex items-center justify-center"
      style={{ background: "var(--bg-primary)" }}
    >
      <div className="text-center max-w-xs">
        <i
          className="fa-solid fa-microchip text-3xl mb-3 block"
          style={{ color: "var(--text-muted)", opacity: 0.3 }}
        />
        <p className="text-sm font-medium mb-1" style={{ color: "var(--text-primary)" }}>
          Disassembler
        </p>
        <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
          {sessionActive
            ? "Enter a memory address above to disassemble, or click an export/symbol in the Module Browser."
            : "Attach to a process first, then enter an address to disassemble."}
        </p>
        {sessionActive && (
          <div className="flex flex-col gap-1.5 text-[10px]" style={{ color: "var(--text-muted)" }}>
            <span><b>Tip:</b> Click an address operand in a jump/call to follow it</span>
            <span><b>Tip:</b> Right-click an address in Module Browser exports to disassemble</span>
            <span><b>Tip:</b> Color coding: <span style={{ color: "#60a5fa" }}>calls</span> <span style={{ color: "#f59e0b" }}>jumps</span> <span style={{ color: "#ef4444" }}>returns</span> <span style={{ color: "#34d399" }}>moves</span></span>
          </div>
        )}
      </div>
    </div>
  );
}

function AsmToolbar({ tabId, ts }: { tabId: string; ts: AsmTabState }) {
  const store = useDisasmStore();
  const bookmarks = useBookmarksStore();

  return (
    <div
      className="shrink-0 border-b"
      style={{ borderColor: "var(--border)", background: "var(--bg-secondary)" }}
    >
      <div className="flex flex-wrap items-center gap-1.5 px-3 py-1.5">
        <input
          type="text"
          value={ts.address}
          onChange={(e) => store.setAddress(tabId, e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") store.disassemble(tabId); }}
          placeholder="0x7fff..."
          className="text-[11px] font-mono px-2 py-1 rounded border outline-none min-w-0"
          style={{
            background: "var(--bg-input)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
            width: 180,
          }}
        />
        <button
          onClick={() => store.disassemble(tabId)}
          disabled={!ts.address.trim() || ts.loading}
          className={`text-[10px] px-2 py-1 rounded font-medium text-white disabled:opacity-40 ${ts.loading ? "loading" : ""}`}
          style={{ background: "var(--accent)" }}
        >
          Go
        </button>

        <div className="w-px h-4" style={{ background: "var(--border)" }} />

        {COUNT_OPTIONS.map((n) => (
          <button
            key={n}
            onClick={() => store.setCount(tabId, n)}
            className="text-[10px] px-1 py-0.5 rounded icon-btn"
            style={{
              color: ts.count === n ? "var(--accent-text)" : "var(--text-muted)",
              background: ts.count === n ? "var(--accent-soft)" : "transparent",
            }}
            title={`${n} instructions`}
          >
            {n}
          </button>
        ))}

        <div className="flex-1" />

        {ts.instructions.length > 0 && (
          <>
            <button
              onClick={() => store.continueForward(tabId)}
              disabled={ts.loading}
              className="text-[10px] px-1.5 py-0.5 rounded border icon-btn"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Load more instructions"
            >
              <i className="fa-solid fa-chevron-down" style={{ fontSize: 8 }} /> More
            </button>
            <button
              onClick={() => {
                if (ts.currentAddress) {
                  navigateToMemory(ts.currentAddress);
                }
              }}
              className="text-[10px] px-1.5 py-0.5 rounded border icon-btn"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Open in Hex Viewer"
            >
              <i className="fa-solid fa-memory" style={{ fontSize: 8 }} />
            </button>
            <button
              onClick={() => {
                if (ts.currentAddress) {
                  bookmarks.add({
                    label: ts.currentAddress,
                    address: ts.currentAddress,
                    type: "asm",
                  });
                }
              }}
              className="text-[10px] px-1.5 py-0.5 rounded border icon-btn"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Bookmark this address"
            >
              <i className="fa-solid fa-bookmark" style={{ fontSize: 8 }} />
            </button>
          </>
        )}

        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
          {ts.instructions.length > 0 && `${ts.instructions.length} insns`}
        </span>
      </div>
    </div>
  );
}

function InsnDetail({ insn }: { insn: Instruction }) {
  const targetAddr = extractAddress(insn.opStr);
  return (
    <div
      className="border-t px-3 py-1.5 shrink-0"
      style={{ borderColor: "var(--border)", background: "var(--bg-secondary)" }}
    >
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[10px]">
        <span>
          <span style={{ color: "var(--text-muted)" }}>Address: </span>
          <span className="cursor-pointer" style={{ color: "var(--text-primary)" }} onClick={() => copyToClipboard(insn.address)}>{insn.address}</span>
        </span>
        <span>
          <span style={{ color: "var(--text-muted)" }}>Size: </span>
          <span style={{ color: "var(--text-primary)" }}>{insn.size} bytes</span>
        </span>
        <span>
          <span style={{ color: "var(--text-muted)" }}>Bytes: </span>
          <span className="cursor-pointer font-mono" style={{ color: "var(--text-primary)" }} onClick={() => copyToClipboard(insn.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" "))}>
            {insn.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")}
          </span>
        </span>
        {targetAddr && (
          <span>
            <span style={{ color: "var(--text-muted)" }}>Target: </span>
            <span
              className="cursor-pointer underline"
              style={{ color: "var(--accent-text)" }}
              onClick={() => navigateToDisasm(targetAddr)}
            >
              {targetAddr}
            </span>
          </span>
        )}
        <span>
          <button
            className="underline"
            style={{ color: "var(--text-muted)" }}
            onClick={() => navigateToMemory(insn.address)}
          >
            View in Hex
          </button>
        </span>
      </div>
    </div>
  );
}

export default function DisassemblerTab({ tabId }: Props) {
  const store = useDisasmStore();
  const ts = store.getTabState(tabId);

  if (ts.instructions.length === 0 && !ts.loading && !ts.error) {
    return (
      <div className="flex flex-col h-full">
        <AsmToolbar tabId={tabId} ts={ts} />
        <AsmWelcome tabId={tabId} />
      </div>
    );
  }

  const selectedInsn = ts.selectedIndex !== null ? ts.instructions[ts.selectedIndex] : null;

  return (
    <div className="flex flex-col h-full">
      <AsmToolbar tabId={tabId} ts={ts} />

      <div className="flex-1 overflow-y-auto" style={{ background: "var(--bg-primary)" }}>
        {ts.error && (
          <div className="text-xs px-3 py-3 text-center" style={{ color: "#ef4444" }}>
            {ts.error}
          </div>
        )}
        {ts.instructions.length > 0 && (
          <AsmListing
            instructions={ts.instructions}
            selectedIndex={ts.selectedIndex}
            onSelect={(i) => store.setSelectedIndex(tabId, i)}
          />
        )}
        {ts.loading && ts.instructions.length === 0 && (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            Disassembling...
          </div>
        )}
      </div>

      {selectedInsn && <InsnDetail insn={selectedInsn} />}
    </div>
  );
}
