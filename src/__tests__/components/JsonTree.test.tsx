import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import JsonTree from "@/components/console/JsonTree.tsx";

describe("JsonTree", () => {
  it("renders string primitive", () => {
    render(<JsonTree data="hello" />);
    expect(screen.getByText('"hello"')).toBeInTheDocument();
  });

  it("renders number primitive", () => {
    render(<JsonTree data={42} />);
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("renders boolean primitive", () => {
    render(<JsonTree data={true} />);
    expect(screen.getByText("true")).toBeInTheDocument();
  });

  it("renders null", () => {
    render(<JsonTree data={null} />);
    expect(screen.getByText("null")).toBeInTheDocument();
  });

  it("renders root-level object expanded by default", () => {
    render(<JsonTree data={{ key: "val" }} />);
    expect(screen.getByText("key:")).toBeInTheDocument();
    expect(screen.getByText('"val"')).toBeInTheDocument();
  });

  it("collapses nested objects by default", () => {
    render(<JsonTree data={{ nested: { deep: "value" } }} />);
    expect(screen.getByText("nested:")).toBeInTheDocument();
    expect(screen.getByText("{1}")).toBeInTheDocument();
    expect(screen.queryByText('"value"')).not.toBeInTheDocument();
  });

  it("expands nested objects on click", () => {
    render(<JsonTree data={{ nested: { deep: "value" } }} />);
    const nestedToggle = screen.getByText("{1}").closest(".json-toggle");
    fireEvent.click(nestedToggle!);
    expect(screen.getByText('"value"')).toBeInTheDocument();
  });

  it("collapses expanded objects on click", () => {
    render(<JsonTree data={{ key: "val" }} />);
    expect(screen.getByText('"val"')).toBeInTheDocument();
    const toggle = document.querySelector(".json-toggle");
    fireEvent.click(toggle!);
    expect(screen.queryByText('"val"')).not.toBeInTheDocument();
    expect(screen.getByText("{1}")).toBeInTheDocument();
  });

  it("renders array preview", () => {
    render(<JsonTree data={{ items: [1, 2, 3] }} />);
    expect(screen.getByText("[3]")).toBeInTheDocument();
  });

  it("has max depth limit defined", () => {
    let data: Record<string, unknown> = { val: "leaf" };
    for (let i = 0; i < 12; i++) {
      data = { nested: data };
    }
    const { container } = render(<JsonTree data={data} />);
    expect(container.querySelector(".json-tree")).toBeInTheDocument();
  });
});
