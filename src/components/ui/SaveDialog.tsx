import { useState, useEffect, useRef } from "react";
import Modal from "./Modal.tsx";

interface Props {
  onSave: (name: string) => void;
  onClose: () => void;
  defaultName?: string;
}

export default function SaveDialog({ onSave, onClose, defaultName = "" }: Props) {
  const [name, setName] = useState(defaultName);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  function handleSubmit() {
    if (name.trim()) {
      onSave(name.trim());
    }
  }

  return (
    <Modal onClose={onClose}>
      <div
        className="rounded-lg border p-4 w-80"
        style={{
          background: "var(--bg-primary)",
          borderColor: "var(--border)",
        }}
      >
        <p
          className="text-sm font-semibold mb-3"
          style={{ color: "var(--text-primary)" }}
        >
          Save Script
        </p>
        <input
          ref={inputRef}
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleSubmit();
            if (e.key === "Escape") onClose();
          }}
          placeholder="Script name"
          className="text-xs px-2.5 py-1.5 rounded border outline-none w-full mb-3"
          style={{
            background: "var(--bg-input)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
          }}
        />
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="text-xs px-3 py-1.5 rounded border"
            style={{
              borderColor: "var(--border)",
              color: "var(--text-secondary)",
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!name.trim()}
            className="text-xs px-3 py-1.5 rounded font-medium text-white disabled:opacity-40"
            style={{ background: "var(--accent)" }}
          >
            Save
          </button>
        </div>
      </div>
    </Modal>
  );
}
