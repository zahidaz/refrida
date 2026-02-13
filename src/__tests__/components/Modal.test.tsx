import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import Modal from "@/components/ui/Modal.tsx";

vi.mock("@/hooks/useIsMobile.ts", () => ({
  useIsMobile: () => false,
  useIsTablet: () => false,
}));

describe("Modal", () => {
  const onClose = vi.fn();

  beforeEach(() => {
    onClose.mockClear();
  });

  it("renders children", () => {
    render(
      <Modal onClose={onClose}>
        <div>Modal Content</div>
      </Modal>,
    );
    expect(screen.getByText("Modal Content")).toBeInTheDocument();
  });

  it("calls onClose on backdrop click", () => {
    const { container } = render(
      <Modal onClose={onClose}>
        <div>Content</div>
      </Modal>,
    );
    const backdrop = container.querySelector(".fixed");
    fireEvent.click(backdrop!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not close on content click", () => {
    render(
      <Modal onClose={onClose}>
        <div>Content</div>
      </Modal>,
    );
    fireEvent.click(screen.getByText("Content"));
    expect(onClose).not.toHaveBeenCalled();
  });

  it("calls onClose on Escape key", () => {
    render(
      <Modal onClose={onClose}>
        <div>Content</div>
      </Modal>,
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("applies custom className", () => {
    const { container } = render(
      <Modal onClose={onClose} className="test-class">
        <div>Content</div>
      </Modal>,
    );
    expect(container.querySelector(".test-class")).toBeInTheDocument();
  });
});
