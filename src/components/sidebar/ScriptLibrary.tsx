import { useScriptsStore } from "@/stores/scripts.ts";

interface Props {
  onLoadScript: (content: string) => void;
}

export default function ScriptLibrary({ onLoadScript }: Props) {
  const { savedScripts, deleteFromLibrary } = useScriptsStore();

  function handleLoad(id: string) {
    const script = savedScripts.find((s) => s.id === id);
    if (script) {
      onLoadScript(script.content);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center px-2 py-1.5 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <span
          className="text-xs font-semibold"
          style={{ color: "var(--text-primary)" }}
        >
          Saved Scripts
        </span>
        <span
          className="text-[10px] ml-1"
          style={{ color: "var(--text-muted)" }}
        >
          ({savedScripts.length})
        </span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {savedScripts.length === 0 ? (
          <div
            className="text-xs px-3 py-4 text-center"
            style={{ color: "var(--text-muted)" }}
          >
            No saved scripts yet.
            <br />
            Use Save in the editor toolbar to add scripts here.
          </div>
        ) : (
          savedScripts.map((s) => (
            <div
              key={s.id}
              className="flex items-center gap-1 px-2 py-1.5 text-xs cursor-pointer group hover-row"
              style={{ color: "var(--text-primary)" }}
              onClick={() => handleLoad(s.id)}
            >
              <i
                className="fa-solid fa-file-code text-[10px] mr-1"
                style={{ color: "var(--text-muted)" }}
              />
              <span className="flex-1 truncate">{s.name}</span>
              <span
                className="text-[10px]"
                style={{ color: "var(--text-muted)" }}
              >
                {new Date(s.date).toLocaleDateString()}
              </span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  deleteFromLibrary(s.id);
                }}
                className="text-red-400 text-[10px] px-1 opacity-0 group-hover:opacity-100"
              >
                Del
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
