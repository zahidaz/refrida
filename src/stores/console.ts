import { create } from "zustand";

export type LogLevel = "info" | "warning" | "error" | "system";

export interface ConsoleLine {
  text: string;
  level: LogLevel;
  timestamp: string;
  runId: number;
}

interface ConsoleState {
  lines: ConsoleLine[];
  search: string;
  filter: LogLevel | "all";
  filterRunId: number | null;
  currentRunId: number;
  exportFormat: "txt" | "json" | "csv";
  copiedIndex: number | null;
  append: (text: string, level?: LogLevel) => void;
  bumpRunId: () => void;
  setFilterRunId: (id: number | null) => void;
  clear: () => void;
  setSearch: (q: string) => void;
  setFilter: (f: LogLevel | "all") => void;
  setExportFormat: (f: "txt" | "json" | "csv") => void;
  setCopiedIndex: (i: number | null) => void;
  copyLine: (line: ConsoleLine, index: number) => void;
  exportConsole: () => void;
}

function formatTimestamp(): string {
  return new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}

export const useConsoleStore = create<ConsoleState>((set, get) => ({
  lines: [],
  search: "",
  filter: "all",
  filterRunId: null,
  currentRunId: 0,
  exportFormat: "txt",
  copiedIndex: null,

  append: (text, level = "info") =>
    set((state) => ({
      lines: [...state.lines, { text, level, timestamp: formatTimestamp(), runId: state.currentRunId }],
    })),

  bumpRunId: () =>
    set((state) => ({ currentRunId: state.currentRunId + 1 })),

  setFilterRunId: (filterRunId) => set({ filterRunId }),

  clear: () => set({ lines: [], filterRunId: null }),
  setSearch: (search) => set({ search }),
  setFilter: (filter) => set({ filter }),
  setExportFormat: (exportFormat) => set({ exportFormat }),
  setCopiedIndex: (copiedIndex) => set({ copiedIndex }),

  copyLine: (line, index) => {
    navigator.clipboard.writeText(line.text).then(() => {
      set({ copiedIndex: index });
      setTimeout(() => set({ copiedIndex: null }), 1200);
    });
  },

  exportConsole: () => {
    const { lines, exportFormat: fmt, append } = get();
    if (lines.length === 0) return;

    let content: string, mime: string, ext: string;

    if (fmt === "json") {
      content = JSON.stringify(
        lines.map((l) => ({
          timestamp: l.timestamp,
          level: l.level,
          text: l.text,
        })),
        null,
        2,
      );
      mime = "application/json";
      ext = "json";
    } else if (fmt === "csv") {
      const header = "timestamp,level,text";
      const rows = lines.map(
        (l) =>
          `"${l.timestamp}","${l.level}","${l.text.replace(/"/g, '""')}"`,
      );
      content = [header, ...rows].join("\n");
      mime = "text/csv";
      ext = "csv";
    } else {
      content = lines
        .map((l) => `${l.timestamp} [${l.level}] ${l.text}`)
        .join("\n");
      mime = "text/plain";
      ext = "txt";
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `refrida-console-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
    append(`Exported ${lines.length} lines as ${ext}.`, "system");
  },
}));

export function getFilteredLines(state: ConsoleState): ConsoleLine[] {
  let result = state.lines;
  if (state.filterRunId !== null) {
    result = result.filter((l) => l.runId === state.filterRunId);
  }
  if (state.filter !== "all") {
    result = result.filter((l) => l.level === state.filter);
  }
  const q = state.search.trim().toLowerCase();
  if (q) {
    result = result.filter((l) => l.text.toLowerCase().includes(q));
  }
  return result;
}

export function getRunIds(state: ConsoleState): number[] {
  const ids = new Set<number>();
  for (const line of state.lines) {
    ids.add(line.runId);
  }
  return Array.from(ids).sort((a, b) => b - a);
}

export function consoleLineClass(level: LogLevel): string {
  const map: Record<string, string> = {
    warning: "text-amber-600 dark:text-amber-400",
    error: "text-red-600 dark:text-red-400",
    system: "text-orange-600 dark:text-orange-400",
  };
  return map[level] || "text-gray-800 dark:text-gray-200";
}

export function isJson(text: string): boolean {
  const t = text.trim();
  if (
    (t.startsWith("{") && t.endsWith("}")) ||
    (t.startsWith("[") && t.endsWith("]"))
  ) {
    try {
      JSON.parse(t);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}
