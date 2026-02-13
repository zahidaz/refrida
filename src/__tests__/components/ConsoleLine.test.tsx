import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import ConsoleLine from "@/components/console/ConsoleLine.tsx";
import { useConsoleStore, type ConsoleLine as ConsoleLineType } from "@/stores/console.ts";

function makeLine(overrides: Partial<ConsoleLineType> = {}): ConsoleLineType {
  return {
    text: "test message",
    level: "info",
    timestamp: "12:00:00",
    runId: 1,
    ...overrides,
  };
}

describe("ConsoleLine", () => {
  beforeEach(() => {
    useConsoleStore.setState({ copiedIndex: null });
  });

  it("renders timestamp", () => {
    render(<ConsoleLine line={makeLine()} index={0} />);
    expect(screen.getByText("12:00:00")).toBeInTheDocument();
  });

  it("renders text content", () => {
    render(<ConsoleLine line={makeLine({ text: "hello world" })} index={0} />);
    expect(screen.getByText("hello world")).toBeInTheDocument();
  });

  it("renders JSON as tree", () => {
    render(<ConsoleLine line={makeLine({ text: '{"key":"value"}' })} index={0} />);
    expect(screen.getByText("key:")).toBeInTheDocument();
  });

  it("renders plain text for non-JSON", () => {
    render(<ConsoleLine line={makeLine({ text: "not json" })} index={0} />);
    expect(screen.getByText("not json")).toBeInTheDocument();
  });

  it("shows copy button", () => {
    render(<ConsoleLine line={makeLine()} index={0} />);
    expect(screen.getByTitle("Copy line")).toBeInTheDocument();
  });
});
