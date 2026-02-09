interface Props {
  line: number;
  col: number;
}

export default function EditorStatusBar({ line, col }: Props) {
  return (
    <div
      className="flex items-center px-2 py-0.5 text-[11px] border-t"
      style={{
        borderColor: "var(--border)",
        color: "var(--text-muted)",
        background: "var(--bg-secondary)",
      }}
    >
      <span>
        Ln {line}, Col {col}
      </span>
    </div>
  );
}
