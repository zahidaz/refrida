import { useState, useMemo, useEffect } from "react";
import { TEMPLATES } from "@/lib/templates.ts";
import { useSnippetsStore, type Snippet } from "@/stores/snippets.ts";
import Modal from "./Modal.tsx";

const CATEGORIES: Record<string, string[]> = {
  "Getting Started": ["hello", "hook-native", "stalker"],
  "iOS Security": ["ssl-pinning-bypass", "objc-observer", "jailbreak-detect-bypass", "keychain-dump"],
  "Android Security": ["ssl-pinning-bypass-android", "java-hook", "root-detect-bypass", "shared-prefs"],
  "Reverse Engineering": ["anti-debug", "crypto-trace", "network-trace", "backtrace"],
};

const ALL_KEYS = Object.keys(TEMPLATES);

type Tab = "builtin" | "community";

interface PreviewData {
  title: string;
  code: string;
}

interface Props {
  onSelect: (name: string, code: string) => void;
  onClose: () => void;
}

export default function TemplateBrowser({ onSelect, onClose }: Props) {
  const [search, setSearch] = useState("");
  const [preview, setPreview] = useState<PreviewData | null>(null);
  const [tab, setTab] = useState<Tab>("builtin");
  const { snippets, loading, error, fetched, fetch: fetchSnippets } = useSnippetsStore();

  useEffect(() => {
    if (tab === "community" && !fetched && !loading) {
      fetchSnippets();
    }
  }, [tab, fetched, loading, fetchSnippets]);

  const filteredBuiltin = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return null;
    return ALL_KEYS.filter((k) => {
      const t = TEMPLATES[k];
      return t.label.toLowerCase().includes(q) || t.code.toLowerCase().includes(q);
    });
  }, [search]);

  const filteredSnippets = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return snippets;
    return snippets.filter((s) => s.title.toLowerCase().includes(q) || s.code.toLowerCase().includes(q));
  }, [search, snippets]);

  function handleSelectBuiltin(key: string) {
    const t = TEMPLATES[key];
    onSelect(t.label, t.code);
    onClose();
  }

  function handleSelectSnippet(s: Snippet) {
    onSelect(s.title, s.code);
    onClose();
  }

  const totalCount = ALL_KEYS.length + snippets.length;

  return (
    <Modal onClose={onClose} align="top">
      <div
        className="rounded-lg border overflow-hidden flex flex-col"
        style={{
          background: "var(--bg-primary)",
          borderColor: "var(--border)",
          width: 720,
          maxWidth: "90vw",
          maxHeight: "75vh",
          boxShadow: "0 16px 48px var(--dropdown-shadow)",
        }}
      >
        <div className="px-4 py-3 border-b shrink-0" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center gap-2 mb-2">
            <i className="fa-solid fa-file-code" style={{ color: "var(--accent-text)", fontSize: 14 }} />
            <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              Script Templates
            </span>
            <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
              ({totalCount} scripts)
            </span>
            <div className="flex-1" />
            <div className="flex gap-0.5">
              {(["builtin", "community"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className="text-[10px] px-2.5 py-0.5 rounded icon-btn"
                  style={{
                    background: tab === t ? "var(--accent)" : "transparent",
                    color: tab === t ? "white" : "var(--text-muted)",
                  }}
                >
                  {t === "builtin" ? "Built-in" : "Community"}
                  {t === "community" && snippets.length > 0 && ` (${snippets.length})`}
                </button>
              ))}
            </div>
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={tab === "builtin" ? "Search built-in templates..." : "Search community snippets (frida-snippets)..."}
            className="text-xs px-3 py-1.5 rounded border outline-none w-full"
            style={{
              background: "var(--bg-input)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
            autoFocus
          />
        </div>

        <div className="flex-1 overflow-y-auto">
          {preview ? (
            <PreviewPane
              preview={preview}
              onBack={() => setPreview(null)}
              onUse={() => {
                onSelect(preview.title, preview.code);
                onClose();
              }}
            />
          ) : tab === "builtin" ? (
            <BuiltinList
              search={search}
              filtered={filteredBuiltin}
              onSelect={handleSelectBuiltin}
              onPreview={(key) => setPreview({ title: TEMPLATES[key].label, code: TEMPLATES[key].code })}
            />
          ) : (
            <CommunityList
              snippets={filteredSnippets}
              loading={loading}
              error={error}
              onSelect={handleSelectSnippet}
              onPreview={(s) => setPreview({ title: s.title, code: s.code })}
              onRetry={fetchSnippets}
            />
          )}
        </div>
      </div>
    </Modal>
  );
}

function PreviewPane({
  preview,
  onBack,
  onUse,
}: {
  preview: PreviewData;
  onBack: () => void;
  onUse: () => void;
}) {
  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-2 px-4 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <button
          onClick={onBack}
          className="text-[10px] px-2 py-0.5 rounded icon-btn"
          style={{ color: "var(--text-secondary)", border: "1px solid var(--border)" }}
        >
          <i className="fa-solid fa-arrow-left" style={{ fontSize: 8 }} /> Back
        </button>
        <span className="text-xs font-medium flex-1 truncate" style={{ color: "var(--text-primary)" }}>
          {preview.title}
        </span>
        <button
          onClick={onUse}
          className="text-[10px] px-3 py-1 rounded font-medium text-white"
          style={{ background: "var(--accent)" }}
        >
          Use Script
        </button>
      </div>
      <pre
        className="flex-1 overflow-auto text-[11px] font-mono p-4 leading-5"
        style={{ color: "var(--text-primary)", background: "var(--bg-tertiary)" }}
      >
        {preview.code}
      </pre>
    </div>
  );
}

function BuiltinList({
  search,
  filtered,
  onSelect,
  onPreview,
}: {
  search: string;
  filtered: string[] | null;
  onSelect: (key: string) => void;
  onPreview: (key: string) => void;
}) {
  if (filtered) {
    if (filtered.length === 0) {
      return (
        <div className="text-xs py-8 text-center" style={{ color: "var(--text-muted)" }}>
          No templates match "{search}"
        </div>
      );
    }
    return (
      <div className="py-1">
        {filtered.map((key) => (
          <ScriptRow
            key={key}
            title={TEMPLATES[key].label}
            code={TEMPLATES[key].code}
            onSelect={() => onSelect(key)}
            onPreview={() => onPreview(key)}
          />
        ))}
      </div>
    );
  }

  return (
    <>
      {Object.entries(CATEGORIES).map(([category, keys]) => (
        <div key={category}>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider px-4 py-1.5 sticky top-0"
            style={{ color: "var(--text-muted)", background: "var(--bg-secondary)" }}
          >
            {category}
          </div>
          {keys.filter((k) => k in TEMPLATES).map((key) => (
            <ScriptRow
              key={key}
              title={TEMPLATES[key].label}
              code={TEMPLATES[key].code}
              onSelect={() => onSelect(key)}
              onPreview={() => onPreview(key)}
            />
          ))}
        </div>
      ))}
    </>
  );
}

function CommunityList({
  snippets,
  loading,
  error,
  onSelect,
  onPreview,
  onRetry,
}: {
  snippets: Snippet[];
  loading: boolean;
  error: string | null;
  onSelect: (s: Snippet) => void;
  onPreview: (s: Snippet) => void;
  onRetry: () => void;
}) {
  if (loading) {
    return (
      <div className="text-xs py-8 text-center" style={{ color: "var(--text-muted)" }}>
        <div className="loading w-4 h-4 mx-auto mb-2" />
        Loading frida-snippets from GitHub...
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-xs py-8 text-center">
        <div style={{ color: "#ef4444" }} className="mb-2">{error}</div>
        <button
          onClick={onRetry}
          className="text-[10px] px-3 py-1 rounded font-medium"
          style={{ color: "var(--accent-text)", border: "1px solid var(--accent)" }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (snippets.length === 0) {
    return (
      <div className="text-xs py-8 text-center" style={{ color: "var(--text-muted)" }}>
        No matching snippets
      </div>
    );
  }

  return (
    <div className="py-1">
      <div
        className="text-[10px] px-4 py-1.5 flex items-center gap-2"
        style={{ color: "var(--text-muted)", background: "var(--bg-secondary)" }}
      >
        <i className="fa-brands fa-github" style={{ fontSize: 11 }} />
        <span className="font-semibold uppercase tracking-wider">frida-snippets</span>
        <span>by iddoeldor</span>
        <div className="flex-1" />
        <span>{snippets.length} scripts</span>
      </div>
      {snippets.map((s) => (
        <ScriptRow
          key={s.index}
          title={s.title}
          code={s.code}
          onSelect={() => onSelect(s)}
          onPreview={() => onPreview(s)}
        />
      ))}
    </div>
  );
}

function ScriptRow({
  title,
  code,
  onSelect,
  onPreview,
}: {
  title: string;
  code: string;
  onSelect: () => void;
  onPreview: () => void;
}) {
  const lineCount = code.split("\n").length;

  return (
    <div
      className="flex items-center gap-3 px-4 py-2 hover-row cursor-pointer group"
      onClick={onSelect}
    >
      <i className="fa-solid fa-file-code text-xs shrink-0" style={{ color: "var(--accent-text)" }} />
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium truncate" style={{ color: "var(--text-primary)" }}>
          {title}
        </div>
        <div className="text-[10px] truncate font-mono" style={{ color: "var(--text-muted)" }}>
          {code.trim().split("\n")[0]}
        </div>
      </div>
      <span className="text-[9px] shrink-0" style={{ color: "var(--text-muted)" }}>
        {lineCount}L
      </span>
      <button
        className="text-[9px] px-1.5 py-0.5 rounded icon-btn shrink-0 opacity-0 group-hover:opacity-100"
        style={{ color: "var(--text-secondary)", border: "1px solid var(--border)" }}
        onClick={(e) => {
          e.stopPropagation();
          onPreview();
        }}
      >
        Preview
      </button>
    </div>
  );
}
