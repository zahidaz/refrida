import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { readMemoryScript, writeMemoryScript } from "@/lib/utilityScripts.ts";

interface MemoryReadResult {
  bytes: number[];
  address: string;
}

interface WriteResult {
  ok: boolean;
  address: string;
  count: number;
}

export interface HexTabState {
  address: string;
  chunkSize: number;
  bytesPerRow: number;
  data: number[] | null;
  currentAddress: string;
  selectedOffset: number | null;
  searchQuery: string;
  searchType: "hex" | "ascii";
  loading: boolean;
  error: string | null;
  dirty: Record<number, number>;
}

const DEFAULT_HEX_STATE: HexTabState = {
  address: "",
  chunkSize: 256,
  bytesPerRow: 16,
  data: null,
  currentAddress: "",
  selectedOffset: null,
  searchQuery: "",
  searchType: "hex",
  loading: false,
  error: null,
  dirty: {},
};

interface MemoryState {
  tabStates: Record<string, HexTabState>;
  getTabState: (tabId: string) => HexTabState;
  setAddress: (tabId: string, address: string) => void;
  setChunkSize: (tabId: string, size: number) => void;
  setBytesPerRow: (tabId: string, n: number) => void;
  setSelectedOffset: (tabId: string, offset: number | null) => void;
  setSearchQuery: (tabId: string, q: string) => void;
  setSearchType: (tabId: string, t: "hex" | "ascii") => void;
  editByte: (tabId: string, offset: number, value: number) => void;
  read: (tabId: string) => Promise<void>;
  readAt: (tabId: string, addr: string) => Promise<void>;
  readNext: (tabId: string) => Promise<void>;
  readPrev: (tabId: string) => Promise<void>;
  writeChanges: (tabId: string) => Promise<void>;
  discardChanges: (tabId: string) => void;
  download: (tabId: string) => void;
  removeTab: (tabId: string) => void;
  reset: () => void;
}

function addHex(hex: string, offset: number): string {
  const n = BigInt(hex) + BigInt(offset);
  return "0x" + n.toString(16);
}

function updateTab(set: (fn: (s: MemoryState) => Partial<MemoryState>) => void, tabId: string, patch: Partial<HexTabState>) {
  set((s) => ({
    tabStates: {
      ...s.tabStates,
      [tabId]: { ...(s.tabStates[tabId] ?? DEFAULT_HEX_STATE), ...patch },
    },
  }));
}

export const useMemoryStore = create<MemoryState>((set, get) => ({
  tabStates: {},

  getTabState: (tabId) => get().tabStates[tabId] ?? DEFAULT_HEX_STATE,

  setAddress: (tabId, address) => updateTab(set, tabId, { address }),
  setChunkSize: (tabId, chunkSize) => updateTab(set, tabId, { chunkSize }),
  setBytesPerRow: (tabId, bytesPerRow) => updateTab(set, tabId, { bytesPerRow }),
  setSelectedOffset: (tabId, selectedOffset) => updateTab(set, tabId, { selectedOffset }),
  setSearchQuery: (tabId, searchQuery) => updateTab(set, tabId, { searchQuery }),
  setSearchType: (tabId, searchType) => updateTab(set, tabId, { searchType }),

  editByte: (tabId, offset, value) => {
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    updateTab(set, tabId, { dirty: { ...ts.dirty, [offset]: value } });
  },

  read: (tabId) => {
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    return get().readAt(tabId, ts.address);
  },

  readAt: async (tabId, addr) => {
    const trimmed = addr.trim();
    if (!trimmed) return;
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    updateTab(set, tabId, { loading: true, error: null, dirty: {} });
    const result = await runUtilityScript<MemoryReadResult>(
      readMemoryScript(trimmed, ts.chunkSize),
    );
    if (result.error) {
      updateTab(set, tabId, { loading: false, error: result.error, data: null });
    } else if (result.data[0]) {
      updateTab(set, tabId, {
        loading: false,
        data: result.data[0].bytes,
        currentAddress: result.data[0].address,
        address: result.data[0].address,
      });
    } else {
      updateTab(set, tabId, { loading: false, error: "No data returned", data: null });
    }
  },

  readNext: (tabId) => {
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    if (!ts.currentAddress) return get().read(tabId);
    return get().readAt(tabId, addHex(ts.currentAddress, ts.chunkSize));
  },

  readPrev: (tabId) => {
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    if (!ts.currentAddress) return get().read(tabId);
    return get().readAt(tabId, addHex(ts.currentAddress, -ts.chunkSize));
  },

  writeChanges: async (tabId) => {
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    if (!ts.currentAddress || Object.keys(ts.dirty).length === 0) return;

    const entries = Object.entries(ts.dirty).map(([k, v]) => [Number(k), v] as [number, number]);
    entries.sort((a, b) => a[0] - b[0]);

    updateTab(set, tabId, { loading: true, error: null });

    let start = entries[0][0];
    let batch: number[] = [];

    async function flush() {
      if (batch.length === 0) return;
      const addr = addHex(ts.currentAddress, start);
      const result = await runUtilityScript<WriteResult>(writeMemoryScript(addr, batch));
      if (result.error) throw new Error(result.error);
    }

    try {
      for (const [offset, value] of entries) {
        if (batch.length > 0 && offset !== start + batch.length) {
          await flush();
          start = offset;
          batch = [];
        }
        batch.push(value);
      }
      await flush();
      updateTab(set, tabId, { dirty: {} });
      await get().readAt(tabId, ts.currentAddress);
    } catch (err) {
      updateTab(set, tabId, {
        loading: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },

  discardChanges: (tabId) => updateTab(set, tabId, { dirty: {} }),

  download: (tabId) => {
    const ts = get().tabStates[tabId] ?? DEFAULT_HEX_STATE;
    if (!ts.data) return;
    const blob = new Uint8Array(ts.data);
    const file = new File([blob], `memory_${ts.currentAddress}_${ts.chunkSize}.bin`, {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(file);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.name;
    a.click();
    URL.revokeObjectURL(url);
  },

  removeTab: (tabId) => {
    set((s) => {
      const { [tabId]: _, ...rest } = s.tabStates;
      return { tabStates: rest };
    });
  },

  reset: () => set({ tabStates: {} }),
}));

export function getDisplayData(state: HexTabState): number[] | null {
  if (!state.data) return null;
  if (Object.keys(state.dirty).length === 0) return state.data;
  const merged = [...state.data];
  for (const [k, v] of Object.entries(state.dirty)) {
    const idx = Number(k);
    if (idx >= 0 && idx < merged.length) merged[idx] = v;
  }
  return merged;
}

export function searchInData(data: number[], query: string, type: "hex" | "ascii"): number[] {
  if (!query.trim()) return [];
  const matches: number[] = [];

  if (type === "hex") {
    const pattern = query.replace(/\s+/g, "").toLowerCase();
    if (pattern.length % 2 !== 0 || !/^[0-9a-f]+$/.test(pattern)) return [];
    const needle: number[] = [];
    for (let i = 0; i < pattern.length; i += 2) {
      needle.push(parseInt(pattern.slice(i, i + 2), 16));
    }
    for (let i = 0; i <= data.length - needle.length; i++) {
      let found = true;
      for (let j = 0; j < needle.length; j++) {
        if (data[i + j] !== needle[j]) { found = false; break; }
      }
      if (found) matches.push(i);
    }
  } else {
    const needle = Array.from(new TextEncoder().encode(query));
    for (let i = 0; i <= data.length - needle.length; i++) {
      let found = true;
      for (let j = 0; j < needle.length; j++) {
        if (data[i + j] !== needle[j]) { found = false; break; }
      }
      if (found) matches.push(i);
    }
  }

  return matches;
}

export function inspectByte(data: number[], offset: number, baseAddress: string): Record<string, string> {
  const result: Record<string, string> = {};
  const addr = BigInt(baseAddress) + BigInt(offset);
  result["Address"] = "0x" + addr.toString(16);
  result["Offset"] = "0x" + offset.toString(16);

  if (offset < data.length) {
    const u8 = data[offset];
    result["UInt8"] = String(u8);
    result["Int8"] = String(u8 > 127 ? u8 - 256 : u8);
    result["Hex"] = "0x" + u8.toString(16).padStart(2, "0");
    result["Binary"] = u8.toString(2).padStart(8, "0");
    result["Char"] = u8 >= 0x20 && u8 <= 0x7e ? `'${String.fromCharCode(u8)}'` : "N/A";
  }

  if (offset + 2 <= data.length) {
    const u16 = data[offset] | (data[offset + 1] << 8);
    result["UInt16 (LE)"] = String(u16);
  }

  if (offset + 4 <= data.length) {
    const u32 = (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
    result["UInt32 (LE)"] = String(u32);
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, u32, true);
    result["Float32 (LE)"] = new DataView(buf).getFloat32(0, true).toFixed(6);
  }

  let str = "";
  for (let i = offset; i < Math.min(offset + 32, data.length); i++) {
    if (data[i] === 0) break;
    if (data[i] >= 0x20 && data[i] <= 0x7e) str += String.fromCharCode(data[i]);
    else break;
  }
  if (str.length > 0) result["String"] = `"${str}"`;

  return result;
}
