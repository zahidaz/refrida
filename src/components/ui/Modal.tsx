import { useEffect, useRef } from "react";
import { useIsMobile } from "@/hooks/useIsMobile.ts";

interface Props {
  onClose: () => void;
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  align?: "center" | "top";
}

export default function Modal({
  onClose,
  children,
  className = "",
  style,
  align = "center",
}: Props) {
  const contentRef = useRef<HTMLDivElement>(null);
  const isMobile = useIsMobile();

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (isMobile) {
    return (
      <div className="fixed inset-0 z-50 flex flex-col" onClick={onClose}>
        <div className="absolute inset-0 bg-black/50" />
        <div
          ref={contentRef}
          className="relative flex-1 flex flex-col overflow-auto"
          style={{ background: "var(--bg-primary)" }}
          onClick={(e) => e.stopPropagation()}
        >
          <div
            className="flex items-center justify-end px-2 py-1 shrink-0 border-b"
            style={{ borderColor: "var(--border)" }}
          >
            <button
              onClick={onClose}
              className="flex items-center justify-center w-10 h-10 rounded"
              style={{ color: "var(--text-secondary)" }}
            >
              <i className="fa-solid fa-xmark" style={{ fontSize: 16 }} />
            </button>
          </div>
          {children}
        </div>
      </div>
    );
  }

  return (
    <div
      className={`fixed inset-0 z-50 flex ${align === "top" ? "pt-[15vh] justify-center" : "items-center justify-center"}`}
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/50" />
      <div
        ref={contentRef}
        className={`relative ${className}`}
        style={style}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}
