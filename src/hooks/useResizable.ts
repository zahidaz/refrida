import { useState, useCallback, useRef } from "react";
import { getItem, setItem } from "@/lib/storage.ts";

const noop = () => {};

export function useResizable(
  storageKey: string,
  defaultValue: number,
  min: number,
  max: number,
  direction: "x" | "y",
  disabled?: boolean,
) {
  const [value, setValue] = useState(() =>
    getItem<number>(storageKey, defaultValue),
  );
  const dragging = useRef(false);
  const startPos = useRef(0);
  const startVal = useRef(0);

  const start = useCallback(
    (pos: number) => {
      dragging.current = true;
      startPos.current = pos;
      startVal.current = value;
      document.body.style.cursor =
        direction === "x" ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";
    },
    [value, direction],
  );

  const move = useCallback(
    (pos: number) => {
      if (!dragging.current) return;
      const delta = pos - startPos.current;
      const next = Math.max(min, Math.min(max, startVal.current + delta));
      setValue(next);
    },
    [min, max],
  );

  const end = useCallback(() => {
    dragging.current = false;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    setValue((current) => {
      setItem(storageKey, current);
      return current;
    });
  }, [storageKey]);

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      start(direction === "x" ? e.clientX : e.clientY);

      const onMouseMove = (ev: MouseEvent) =>
        move(direction === "x" ? ev.clientX : ev.clientY);
      const onMouseUp = () => {
        end();
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
      };

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    },
    [start, move, end, direction],
  );

  const onTouchStart = useCallback(
    (e: React.TouchEvent) => {
      const touch = e.touches[0];
      start(direction === "x" ? touch.clientX : touch.clientY);

      const onTouchMove = (ev: TouchEvent) => {
        ev.preventDefault();
        move(direction === "x" ? ev.touches[0].clientX : ev.touches[0].clientY);
      };
      const onTouchEnd = () => {
        end();
        document.removeEventListener("touchmove", onTouchMove);
        document.removeEventListener("touchend", onTouchEnd);
      };

      document.addEventListener("touchmove", onTouchMove, { passive: false });
      document.addEventListener("touchend", onTouchEnd);
    },
    [start, move, end, direction],
  );

  if (disabled) {
    return { value, onMouseDown: noop as unknown as typeof onMouseDown, onTouchStart: noop as unknown as typeof onTouchStart };
  }

  return { value, onMouseDown, onTouchStart };
}

export function useResizablePercent(
  storageKey: string,
  defaultValue: number,
  min: number,
  max: number,
  containerSelector: string,
  disabled?: boolean,
) {
  const [value, setValue] = useState(() =>
    getItem<number>(storageKey, defaultValue),
  );
  const dragging = useRef(false);

  const calcPercent = useCallback(
    (clientY: number) => {
      const container = document.querySelector(containerSelector);
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const pct = ((clientY - rect.top) / rect.height) * 100;
      setValue(Math.max(min, Math.min(max, pct)));
    },
    [containerSelector, min, max],
  );

  const end = useCallback(() => {
    dragging.current = false;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    setValue((current) => {
      setItem(storageKey, current);
      return current;
    });
  }, [storageKey]);

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      dragging.current = true;
      document.body.style.cursor = "row-resize";
      document.body.style.userSelect = "none";
      e.preventDefault();

      const onMouseMove = (ev: MouseEvent) => {
        if (!dragging.current) return;
        calcPercent(ev.clientY);
      };
      const onMouseUp = () => {
        end();
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
      };

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    },
    [calcPercent, end],
  );

  const onTouchStart = useCallback(
    (e: React.TouchEvent) => {
      dragging.current = true;
      e.preventDefault();

      const onTouchMove = (ev: TouchEvent) => {
        ev.preventDefault();
        if (!dragging.current) return;
        calcPercent(ev.touches[0].clientY);
      };
      const onTouchEnd = () => {
        end();
        document.removeEventListener("touchmove", onTouchMove);
        document.removeEventListener("touchend", onTouchEnd);
      };

      document.addEventListener("touchmove", onTouchMove, { passive: false });
      document.addEventListener("touchend", onTouchEnd);
    },
    [calcPercent, end],
  );

  if (disabled) {
    return { value, onMouseDown: noop as unknown as typeof onMouseDown, onTouchStart: noop as unknown as typeof onTouchStart };
  }

  return { value, onMouseDown, onTouchStart };
}
