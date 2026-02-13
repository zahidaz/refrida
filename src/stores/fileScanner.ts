import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { scanFileSignaturesScript, dumpFileFromMemoryScript } from "@/lib/utilityScripts.ts";

export interface FileMatch {
  address: string;
  fileType: string;
  module: string | null;
  offset: string | null;
}

interface DumpChunk {
  offset: number;
  bytes: number[];
}

const FILE_TYPE_SIZES: Record<string, number> = {
  PNG: 65536,
  JPEG: 131072,
  GIF: 65536,
  PDF: 262144,
  ZIP: 131072,
  ELF: 65536,
  MachO: 65536,
  PE: 65536,
  SQLite: 65536,
  DEX: 131072,
  BPLIST: 32768,
  PEM: 8192,
  GZIP: 65536,
  BZ2: 65536,
  "7Z": 65536,
  OGG: 131072,
  FLAC: 131072,
  RIFF: 131072,
};

interface FileScannerState {
  results: FileMatch[];
  loading: boolean;
  error: string | null;
  filterType: string;
  filterSearch: string;
  sortBy: "type" | "address" | "module";
  scanned: boolean;
  scan: () => Promise<void>;
  dumpFile: (address: string, fileType: string) => Promise<void>;
  setFilterType: (t: string) => void;
  setFilterSearch: (s: string) => void;
  setSortBy: (s: "type" | "address" | "module") => void;
  reset: () => void;
}

export const useFileScannerStore = create<FileScannerState>((set) => ({
  results: [],
  loading: false,
  error: null,
  filterType: "",
  filterSearch: "",
  sortBy: "type",
  scanned: false,

  setFilterType: (filterType) => set({ filterType }),
  setFilterSearch: (filterSearch) => set({ filterSearch }),
  setSortBy: (sortBy) => set({ sortBy }),

  scan: async () => {
    set({ loading: true, error: null, results: [], scanned: false });
    const result = await runUtilityScript<FileMatch>(scanFileSignaturesScript(), "file-scan");
    if (result.error) {
      set({ loading: false, error: result.error, scanned: true });
    } else {
      set({ loading: false, results: result.data, scanned: true });
    }
  },

  dumpFile: async (address, fileType) => {
    const maxSize = FILE_TYPE_SIZES[fileType] ?? 65536;
    const result = await runUtilityScript<DumpChunk>(dumpFileFromMemoryScript(address, maxSize), `dump-file:${address}`);
    if (result.error) return;

    const chunks = result.data.sort((a, b) => a.offset - b.offset);
    let totalSize = 0;
    for (const c of chunks) totalSize = Math.max(totalSize, c.offset + c.bytes.length);
    const merged = new Uint8Array(totalSize);
    for (const c of chunks) merged.set(c.bytes, c.offset);

    const ext = fileType.toLowerCase();
    const blob = new Blob([merged], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${address}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  },

  reset: () => set({ results: [], loading: false, error: null, scanned: false, filterType: "", filterSearch: "" }),
}));
