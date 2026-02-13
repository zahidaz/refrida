import { create } from "zustand";

export interface Snippet {
  title: string;
  code: string;
  index: number;
}

interface SnippetsState {
  snippets: Snippet[];
  loading: boolean;
  error: string | null;
  fetched: boolean;
  fetch: () => Promise<void>;
}

const RAW_URL = "https://raw.githubusercontent.com/iddoeldor/frida-snippets/master/README.md";

function parseSnippets(md: string): Snippet[] {
  const results: Snippet[] = [];
  const lines = md.split("\n");
  let currentTitle = "";
  let inCodeBlock = false;
  let codeLines: string[] = [];
  let index = 0;

  for (const line of lines) {
    if (/^#{2,6}\s/.test(line)) {
      const title = line.replace(/^#+\s*/, "").replace(/\d+\.\s*/, "").trim();
      if (title.toLowerCase() !== "table of contents") {
        currentTitle = title;
      }
    }

    if (line.startsWith("```js") || line.startsWith("```javascript")) {
      inCodeBlock = true;
      codeLines = [];
      continue;
    }

    if (inCodeBlock && line.startsWith("```")) {
      inCodeBlock = false;
      const code = codeLines.join("\n").trim();
      if (code && currentTitle && !code.startsWith("frida ") && !code.startsWith("pip ")) {
        results.push({ title: currentTitle, code, index: index++ });
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
    }
  }

  return results;
}

export const useSnippetsStore = create<SnippetsState>((set, get) => ({
  snippets: [],
  loading: false,
  error: null,
  fetched: false,

  fetch: async () => {
    if (get().fetched || get().loading) return;
    set({ loading: true, error: null });
    try {
      const resp = await window.fetch(RAW_URL);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const md = await resp.text();
      const snippets = parseSnippets(md);
      set({ snippets, loading: false, fetched: true });
    } catch (err) {
      set({ loading: false, error: err instanceof Error ? err.message : String(err) });
    }
  },
}));
