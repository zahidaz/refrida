import { describe, it, expect } from "vitest";
import { TEMPLATES } from "@/lib/templates.ts";

describe("templates", () => {
  const templateKeys = Object.keys(TEMPLATES);

  it("has expected template count", () => {
    expect(templateKeys.length).toBeGreaterThanOrEqual(14);
  });

  it.each(templateKeys)("template '%s' has a non-empty label", (key) => {
    expect(TEMPLATES[key].label).toBeTruthy();
    expect(TEMPLATES[key].label.length).toBeGreaterThan(0);
  });

  it.each(templateKeys)("template '%s' has non-empty code", (key) => {
    expect(TEMPLATES[key].code).toBeTruthy();
    expect(TEMPLATES[key].code.trim().length).toBeGreaterThan(0);
  });

  it("contains expected templates", () => {
    expect(TEMPLATES).toHaveProperty("hello");
    expect(TEMPLATES).toHaveProperty("hook-native");
    expect(TEMPLATES).toHaveProperty("stalker");
    expect(TEMPLATES).toHaveProperty("ssl-pinning-bypass");
    expect(TEMPLATES).toHaveProperty("anti-debug");
    expect(TEMPLATES).toHaveProperty("crypto-trace");
    expect(TEMPLATES).toHaveProperty("network-trace");
    expect(TEMPLATES).toHaveProperty("backtrace");
  });
});
