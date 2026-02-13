import { useEffect, useMemo, useState } from "react";
import {
  useMemoryStore,
  getDisplayData,
  searchInData,
  inspectByte,
  type HexTabState,
} from "@/stores/memory.ts";
import { useSessionStore } from "@/stores/session.ts";
import { useScriptsStore } from "@/stores/scripts.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

const CHUNK_SIZES = [128, 256, 512, 1024, 2048];
const BYTES_PER_ROW_OPTIONS = [8, 16, 32];

interface Props {
  tabId: string;
}

function HexGrid({
  data,
  baseAddress,
  bytesPerRow,
  selectedOffset,
  highlights,
  dirty,
  onSelect,
  onEditByte,
}: {
  data: number[];
  baseAddress: string;
  bytesPerRow: number;
  selectedOffset: number | null;
  highlights: Set<number>;
  dirty: Record<number, number>;
  onSelect: (offset: number) => void;
  onEditByte: (offset: number, value: number) => void;
}) {
  const [editingOffset, setEditingOffset] = useState<number | null>(null);
  const [editValue, setEditValue] = useState("");
  const base = BigInt(baseAddress);

  const rows = useMemo(() => {
    const result: Array<{ rowOffset: number; offsetStr: string; bytes: number[]; ascii: string }> = [];
    for (let i = 0; i < data.length; i += bytesPerRow) {
      const chunk = data.slice(i, i + bytesPerRow);
      const offsetStr = (base + BigInt(i)).toString(16).padStart(8, "0");
      const ascii = chunk
        .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
        .join("");
      result.push({ rowOffset: i, offsetStr, bytes: chunk, ascii });
    }
    return result;
  }, [data, bytesPerRow, base]);

  function commitEdit(offset: number) {
    const parsed = parseInt(editValue, 16);
    if (!isNaN(parsed) && parsed >= 0 && parsed <= 255) {
      onEditByte(offset, parsed);
    }
    setEditingOffset(null);
    setEditValue("");
  }

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
        <span className="shrink-0" style={{ width: 72 }}>Offset</span>
        <span className="flex-1">
          {Array.from({ length: bytesPerRow }, (_, i) => (
            <span key={i} className="inline-block" style={{ width: "1.8em", textAlign: "center" }}>
              {i.toString(16).padStart(2, "0").toUpperCase()}
            </span>
          ))}
        </span>
        <span className="ml-2">ASCII</span>
      </div>
      {rows.map((row) => (
        <div key={row.offsetStr} className="flex px-3 hover-row">
          <span
            className="shrink-0 cursor-pointer"
            style={{ width: 72, color: "var(--text-muted)" }}
            onClick={() => copyToClipboard("0x" + row.offsetStr)}
            title="Copy address"
          >
            {row.offsetStr}
          </span>
          <span className="flex-1">
            {row.bytes.map((byte, j) => {
              const globalOffset = row.rowOffset + j;
              const isDirty = globalOffset in dirty;
              const isSelected = selectedOffset === globalOffset;
              const isHighlight = highlights.has(globalOffset);

              if (editingOffset === globalOffset) {
                return (
                  <input
                    key={j}
                    autoFocus
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value.slice(0, 2))}
                    onBlur={() => commitEdit(globalOffset)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitEdit(globalOffset);
                      if (e.key === "Escape") { setEditingOffset(null); setEditValue(""); }
                    }}
                    className="inline-block text-center bg-transparent outline-none border-b"
                    style={{
                      width: "1.8em",
                      color: "var(--accent-text)",
                      borderColor: "var(--accent)",
                    }}
                  />
                );
              }

              return (
                <span
                  key={j}
                  className="inline-block text-center cursor-pointer"
                  style={{
                    width: "1.8em",
                    color: isDirty
                      ? "#ef4444"
                      : isHighlight
                        ? "#fbbf24"
                        : byte === 0
                          ? "var(--text-muted)"
                          : "var(--text-primary)",
                    background: isSelected
                      ? "var(--accent-soft)"
                      : "transparent",
                    borderRadius: isSelected ? 2 : 0,
                  }}
                  onClick={() => onSelect(globalOffset)}
                  onDoubleClick={() => {
                    setEditingOffset(globalOffset);
                    setEditValue(byte.toString(16).padStart(2, "0"));
                  }}
                  title={`Offset 0x${globalOffset.toString(16)} — Double-click to edit`}
                >
                  {byte.toString(16).padStart(2, "0")}
                </span>
              );
            })}
          </span>
          <span className="shrink-0 ml-2" style={{ color: "var(--json-string)" }}>
            {row.ascii}
          </span>
        </div>
      ))}
    </div>
  );
}

function DataInspector({ data, offset, baseAddress }: { data: number[]; offset: number; baseAddress: string }) {
  const info = inspectByte(data, offset, baseAddress);
  return (
    <div
      className="border-t px-3 py-1.5 shrink-0"
      style={{ borderColor: "var(--border)", background: "var(--bg-secondary)" }}
    >
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[10px]">
        {Object.entries(info).map(([key, value]) => (
          <span key={key}>
            <span style={{ color: "var(--text-muted)" }}>{key}: </span>
            <span
              className="cursor-pointer"
              style={{ color: "var(--text-primary)" }}
              onClick={() => copyToClipboard(value)}
              title="Click to copy"
            >
              {value}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

function HexWelcome({ tabId, onNavigate }: { tabId: string; onNavigate: (addr: string) => void }) {
  const sessionActive = useSessionStore((s) => s.sessionActive);
  const tab = useScriptsStore((s) => s.tabs.find((t) => t.id === tabId));

  useEffect(() => {
    if (sessionActive && tab?.address) {
      onNavigate(tab.address);
    }
  }, [sessionActive, tab?.address]);

  return (
    <div
      className="flex-1 flex items-center justify-center"
      style={{ background: "var(--bg-primary)" }}
    >
      <div className="text-center max-w-xs">
        <i
          className="fa-solid fa-memory text-3xl mb-3 block"
          style={{ color: "var(--text-muted)", opacity: 0.3 }}
        />
        <p className="text-sm font-medium mb-1" style={{ color: "var(--text-primary)" }}>
          Hex Memory Viewer
        </p>
        <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
          {sessionActive
            ? "Enter a memory address above to start exploring, or browse modules and click an address to jump here."
            : "Attach to a process first, then enter a memory address to inspect."}
        </p>
        {sessionActive && (
          <div className="flex flex-col gap-1.5 text-[10px]" style={{ color: "var(--text-muted)" }}>
            <span><b>Tip:</b> Double-click a byte to edit it in place</span>
            <span><b>Tip:</b> Click any address in the Module Browser to open it here</span>
            <span><b>Tip:</b> Use the search bar to find hex patterns or ASCII strings</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function HexViewerTab({ tabId }: Props) {
  const store = useMemoryStore();
  const ts = store.getTabState(tabId);
  const displayData = getDisplayData(ts);
  const hasDirty = Object.keys(ts.dirty).length > 0;

  const highlights = useMemo(() => {
    if (!displayData || !ts.searchQuery.trim()) return new Set<number>();
    return new Set(searchInData(displayData, ts.searchQuery, ts.searchType));
  }, [displayData, ts.searchQuery, ts.searchType]);

  function handleNavigate(addr: string) {
    store.setAddress(tabId, addr);
    store.readAt(tabId, addr);
  }

  if (!displayData && !ts.loading && !ts.error) {
    return (
      <div className="flex flex-col h-full">
        <HexToolbar tabId={tabId} ts={ts} hasDirty={hasDirty} highlightCount={highlights.size} onNavigate={handleNavigate} />
        <HexWelcome tabId={tabId} onNavigate={handleNavigate} />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <HexToolbar tabId={tabId} ts={ts} hasDirty={hasDirty} highlightCount={highlights.size} onNavigate={handleNavigate} />

      <div className="flex-1 overflow-y-auto" style={{ background: "var(--bg-primary)" }}>
        {ts.error && (
          <div className="text-xs px-3 py-3 text-center" style={{ color: "#ef4444" }}>
            {ts.error}
          </div>
        )}
        {displayData && ts.currentAddress && (
          <HexGrid
            data={displayData}
            baseAddress={ts.currentAddress}
            bytesPerRow={ts.bytesPerRow}
            selectedOffset={ts.selectedOffset}
            highlights={highlights}
            dirty={ts.dirty}
            onSelect={(offset) => store.setSelectedOffset(tabId, offset)}
            onEditByte={(offset, value) => store.editByte(tabId, offset, value)}
          />
        )}
        {ts.loading && !displayData && (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            Reading memory...
          </div>
        )}
      </div>

      {displayData && ts.selectedOffset !== null && ts.currentAddress && (
        <DataInspector
          data={displayData}
          offset={ts.selectedOffset}
          baseAddress={ts.currentAddress}
        />
      )}
    </div>
  );
}

function HexToolbar({
  tabId,
  ts,
  hasDirty,
  highlightCount,
  onNavigate,
}: {
  tabId: string;
  ts: HexTabState;
  hasDirty: boolean;
  highlightCount: number;
  onNavigate: (addr: string) => void;
}) {
  const store = useMemoryStore();

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
          onKeyDown={(e) => { if (e.key === "Enter") onNavigate(ts.address); }}
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
          onClick={() => onNavigate(ts.address)}
          disabled={!ts.address.trim() || ts.loading}
          className={`text-[10px] px-2 py-1 rounded font-medium text-white disabled:opacity-40 ${ts.loading ? "loading" : ""}`}
          style={{ background: "var(--accent)" }}
        >
          Go
        </button>

        <div className="w-px h-4" style={{ background: "var(--border)" }} />

        {CHUNK_SIZES.map((size) => (
          <button
            key={size}
            onClick={() => store.setChunkSize(tabId, size)}
            className="text-[10px] px-1 py-0.5 rounded"
            style={{
              color: ts.chunkSize === size ? "var(--accent-text)" : "var(--text-muted)",
              background: ts.chunkSize === size ? "var(--accent-soft)" : "transparent",
            }}
          >
            {size}
          </button>
        ))}

        <div className="w-px h-4" style={{ background: "var(--border)" }} />

        {BYTES_PER_ROW_OPTIONS.map((n) => (
          <button
            key={n}
            onClick={() => store.setBytesPerRow(tabId, n)}
            className="text-[10px] px-1 py-0.5 rounded"
            style={{
              color: ts.bytesPerRow === n ? "var(--accent-text)" : "var(--text-muted)",
              background: ts.bytesPerRow === n ? "var(--accent-soft)" : "transparent",
            }}
            title={`${n} bytes per row`}
          >
            {n}w
          </button>
        ))}

        <div className="flex-1" />

        {ts.data && (
          <>
            <button
              onClick={() => store.readPrev(tabId)}
              disabled={ts.loading}
              className="text-[10px] px-1.5 py-0.5 rounded border"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Previous chunk"
            >
              <i className="fa-solid fa-chevron-left" style={{ fontSize: 8 }} />
            </button>
            <button
              onClick={() => store.readNext(tabId)}
              disabled={ts.loading}
              className="text-[10px] px-1.5 py-0.5 rounded border"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Next chunk"
            >
              <i className="fa-solid fa-chevron-right" style={{ fontSize: 8 }} />
            </button>
            <button
              onClick={() => store.read(tabId)}
              disabled={ts.loading}
              className="text-[10px] px-1.5 py-0.5 rounded border"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Refresh"
            >
              <i className="fa-solid fa-arrows-rotate" style={{ fontSize: 8 }} />
            </button>
            <button
              onClick={() => store.download(tabId)}
              className="text-[10px] px-1.5 py-0.5 rounded border"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Download as binary"
            >
              <i className="fa-solid fa-download" style={{ fontSize: 8 }} />
            </button>
          </>
        )}

        {hasDirty && (
          <>
            <button
              onClick={() => store.writeChanges(tabId)}
              disabled={ts.loading}
              className="text-[10px] px-2 py-0.5 rounded font-medium text-white"
              style={{ background: "#ef4444" }}
              title="Write changes to memory"
            >
              Write
            </button>
            <button
              onClick={() => store.discardChanges(tabId)}
              className="text-[10px] px-1.5 py-0.5 rounded border"
              style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
              title="Discard changes"
            >
              Discard
            </button>
          </>
        )}
      </div>

      {ts.data && (
        <div
          className="flex items-center gap-1.5 px-3 py-1 border-t"
          style={{ borderColor: "var(--border)" }}
        >
          <div className="flex gap-0.5">
            {(["hex", "ascii"] as const).map((t) => (
              <button
                key={t}
                onClick={() => store.setSearchType(tabId, t)}
                className="text-[9px] px-1.5 py-0.5 rounded"
                style={{
                  background: ts.searchType === t ? "var(--accent)" : "transparent",
                  color: ts.searchType === t ? "white" : "var(--text-muted)",
                }}
              >
                {t.toUpperCase()}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={ts.searchQuery}
            onChange={(e) => store.setSearchQuery(tabId, e.target.value)}
            placeholder={ts.searchType === "hex" ? "Search hex: 48 65 6c 6c 6f" : "Search ASCII: Hello"}
            className="text-[10px] font-mono px-2 py-0.5 rounded border outline-none flex-1 min-w-0"
            style={{
              background: "var(--bg-input)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
          />
          {highlightCount > 0 && (
            <span className="text-[9px]" style={{ color: "var(--accent-text)" }}>
              {highlightCount} match{highlightCount !== 1 ? "es" : ""}
            </span>
          )}
          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            {ts.currentAddress} — {ts.data.length} bytes
          </span>
        </div>
      )}
    </div>
  );
}
