import { useEffect, useRef } from "react";

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

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

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
