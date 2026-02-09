import { useState, useCallback, useRef } from "react";
import { getItem, setItem } from "@/lib/storage.ts";

export function useResizable(
  storageKey: string,
  defaultValue: number,
  min: number,
  max: number,
  direction: "x" | "y",
) {
  const [value, setValue] = useState(() =>
    getItem<number>(storageKey, defaultValue),
  );
  const dragging = useRef(false);
  const startPos = useRef(0);
  const startVal = useRef(0);

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      dragging.current = true;
      startPos.current = direction === "x" ? e.clientX : e.clientY;
      startVal.current = value;
      document.body.style.cursor =
        direction === "x" ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";

      const onMouseMove = (ev: MouseEvent) => {
        if (!dragging.current) return;
        const delta =
          (direction === "x" ? ev.clientX : ev.clientY) - startPos.current;
        const next = Math.max(min, Math.min(max, startVal.current + delta));
        setValue(next);
      };

      const onMouseUp = () => {
        dragging.current = false;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
        setValue((current) => {
          setItem(storageKey, current);
          return current;
        });
      };

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    },
    [value, storageKey, min, max, direction],
  );

  return { value, onMouseDown };
}

export function useResizablePercent(
  storageKey: string,
  defaultValue: number,
  min: number,
  max: number,
  containerSelector: string,
) {
  const [value, setValue] = useState(() =>
    getItem<number>(storageKey, defaultValue),
  );
  const dragging = useRef(false);

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      dragging.current = true;
      document.body.style.cursor = "row-resize";
      document.body.style.userSelect = "none";
      e.preventDefault();

      const onMouseMove = (ev: MouseEvent) => {
        if (!dragging.current) return;
        const container = document.querySelector(containerSelector);
        if (!container) return;
        const rect = container.getBoundingClientRect();
        const pct = ((ev.clientY - rect.top) / rect.height) * 100;
        setValue(Math.max(min, Math.min(max, pct)));
      };

      const onMouseUp = () => {
        dragging.current = false;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
        setValue((current) => {
          setItem(storageKey, current);
          return current;
        });
      };

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    },
    [storageKey, min, max, containerSelector],
  );

  return { value, onMouseDown };
}
