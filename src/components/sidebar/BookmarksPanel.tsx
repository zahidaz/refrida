import { useState, useEffect } from "react";
import { useBookmarksStore, type Bookmark } from "@/stores/bookmarks.ts";
import { navigateToMemory, navigateToDisasm } from "@/lib/navigation.ts";
import { copyToClipboard } from "@/lib/clipboard.ts";

function BookmarkRow({
  bookmark,
  editing,
  onStartEdit,
  onRename,
  onRemove,
}: {
  bookmark: Bookmark;
  editing: boolean;
  onStartEdit: () => void;
  onRename: (label: string) => void;
  onRemove: () => void;
}) {
  const [editValue, setEditValue] = useState(bookmark.label);

  function commit() {
    if (editValue.trim()) onRename(editValue.trim());
  }

  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 hover-row cursor-pointer group"
      onClick={() => {
        if (bookmark.type === "asm") navigateToDisasm(bookmark.address);
        else navigateToMemory(bookmark.address);
      }}
    >
      <i
        className={`fa-solid ${bookmark.type === "asm" ? "fa-microchip" : "fa-memory"} shrink-0`}
        style={{ fontSize: 10, color: bookmark.type === "asm" ? "#f59e0b" : "var(--accent-text)" }}
      />
      <div className="flex-1 min-w-0">
        {editing ? (
          <input
            autoFocus
            value={editValue}
            onChange={(e) => setEditValue(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
              if (e.key === "Enter") commit();
              if (e.key === "Escape") onRename(bookmark.label);
            }}
            className="text-[11px] bg-transparent outline-none border-b w-full"
            style={{ color: "var(--text-primary)", borderColor: "var(--accent)" }}
            onClick={(e) => e.stopPropagation()}
          />
        ) : (
          <span
            className="text-[11px] truncate block"
            style={{ color: "var(--text-primary)" }}
            onDoubleClick={(e) => { e.stopPropagation(); onStartEdit(); }}
            title="Double-click to rename"
          >
            {bookmark.label}
          </span>
        )}
        <span className="text-[9px] font-mono block truncate" style={{ color: "var(--text-muted)" }}>
          {bookmark.address}
          {bookmark.module && ` · ${bookmark.module}`}
        </span>
      </div>
      <button
        className="text-[9px] px-1 rounded icon-btn shrink-0 opacity-0 group-hover:opacity-70"
        style={{ color: "var(--text-muted)" }}
        onClick={(e) => {
          e.stopPropagation();
          copyToClipboard(bookmark.address);
        }}
        title="Copy address"
      >
        <i className="fa-solid fa-copy" style={{ fontSize: 8 }} />
      </button>
      <button
        className="text-[9px] px-1 rounded icon-btn shrink-0 opacity-0 group-hover:opacity-70"
        style={{ color: "#ef4444" }}
        onClick={(e) => { e.stopPropagation(); onRemove(); }}
        title="Remove"
      >
        <i className="fa-solid fa-xmark" style={{ fontSize: 9 }} />
      </button>
    </div>
  );
}

export default function BookmarksPanel() {
  const { bookmarks, load, remove, rename } = useBookmarksStore();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => { load(); }, []);

  const filtered = filter.trim()
    ? bookmarks.filter((b) =>
        b.label.toLowerCase().includes(filter.toLowerCase()) ||
        b.address.toLowerCase().includes(filter.toLowerCase()) ||
        (b.module?.toLowerCase().includes(filter.toLowerCase()) ?? false)
      )
    : bookmarks;

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-1.5 px-3 py-2 border-b shrink-0"
        style={{ borderColor: "var(--border)" }}
      >
        <i className="fa-solid fa-bookmark" style={{ fontSize: 11, color: "var(--text-muted)" }} />
        <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
          Bookmarks
        </span>
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
          ({bookmarks.length})
        </span>
      </div>

      {bookmarks.length > 5 && (
        <div className="px-3 py-1.5 shrink-0">
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter bookmarks..."
            className="text-[11px] px-2 py-1 rounded border outline-none w-full"
            style={{
              background: "var(--bg-input)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
          />
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        {filtered.map((b) => (
          <BookmarkRow
            key={b.id}
            bookmark={b}
            editing={editingId === b.id}
            onStartEdit={() => setEditingId(b.id)}
            onRename={(label) => { rename(b.id, label); setEditingId(null); }}
            onRemove={() => remove(b.id)}
          />
        ))}

        {bookmarks.length === 0 && (
          <div className="flex-1 flex items-center justify-center px-6 py-8">
            <div className="text-center" style={{ color: "var(--text-muted)" }}>
              <i
                className="fa-solid fa-bookmark text-2xl mb-3 block"
                style={{ opacity: 0.3 }}
              />
              <p className="text-xs mb-2">No bookmarks yet</p>
              <p className="text-[10px]">
                Bookmark addresses from the Hex Viewer or Disassembler to quickly revisit them.
              </p>
            </div>
          </div>
        )}

        {bookmarks.length > 0 && filtered.length === 0 && (
          <div className="text-xs px-3 py-4 text-center" style={{ color: "var(--text-muted)" }}>
            No matching bookmarks
          </div>
        )}
      </div>
    </div>
  );
}
