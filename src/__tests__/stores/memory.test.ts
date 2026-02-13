import { describe, it, expect } from "vitest";
import { getDisplayData, searchInData, inspectByte } from "@/stores/memory.ts";
import type { HexTabState } from "@/stores/memory.ts";

function makeState(overrides: Partial<HexTabState> = {}): HexTabState {
  return {
    address: "0x1000",
    chunkSize: 256,
    bytesPerRow: 16,
    data: null,
    currentAddress: "0x1000",
    selectedOffset: null,
    searchQuery: "",
    searchType: "hex",
    loading: false,
    error: null,
    dirty: {},
    ...overrides,
  };
}

describe("memory functions", () => {
  describe("getDisplayData", () => {
    it("returns null when data is null", () => {
      expect(getDisplayData(makeState())).toBeNull();
    });

    it("returns raw data when dirty is empty", () => {
      const data = [0x00, 0x01, 0x02, 0x03];
      expect(getDisplayData(makeState({ data }))).toEqual(data);
    });

    it("merges dirty edits over raw data", () => {
      const data = [0x00, 0x01, 0x02, 0x03];
      const dirty = { 1: 0xFF, 3: 0xAA };
      const result = getDisplayData(makeState({ data, dirty }));
      expect(result).toEqual([0x00, 0xFF, 0x02, 0xAA]);
    });

    it("ignores dirty edits outside data range", () => {
      const data = [0x00, 0x01];
      const dirty = { 5: 0xFF };
      const result = getDisplayData(makeState({ data, dirty }));
      expect(result).toEqual([0x00, 0x01]);
    });
  });

  describe("searchInData", () => {
    describe("hex mode", () => {
      it("finds hex pattern in data", () => {
        const data = [0xFF, 0x00, 0xAA, 0xBB];
        expect(searchInData(data, "FF00", "hex")).toEqual([0]);
      });

      it("finds hex pattern with spaces", () => {
        const data = [0x00, 0xFF, 0x00, 0xAA];
        expect(searchInData(data, "FF 00", "hex")).toEqual([1]);
      });

      it("finds multiple matches", () => {
        const data = [0xAA, 0xBB, 0xAA, 0xBB];
        expect(searchInData(data, "AABB", "hex")).toEqual([0, 2]);
      });

      it("returns empty for odd-length hex", () => {
        expect(searchInData([0xFF], "F", "hex")).toEqual([]);
      });

      it("returns empty for non-hex characters", () => {
        expect(searchInData([0xFF], "GG", "hex")).toEqual([]);
      });

      it("returns empty for empty query", () => {
        expect(searchInData([0xFF], "", "hex")).toEqual([]);
      });
    });

    describe("ascii mode", () => {
      it("finds ASCII string in data", () => {
        const data = [0x68, 0x65, 0x6C, 0x6C, 0x6F];
        expect(searchInData(data, "hello", "ascii")).toEqual([0]);
      });

      it("finds partial match", () => {
        const data = [0x41, 0x42, 0x43, 0x44];
        expect(searchInData(data, "BC", "ascii")).toEqual([1]);
      });

      it("returns empty when not found", () => {
        const data = [0x41, 0x42];
        expect(searchInData(data, "xyz", "ascii")).toEqual([]);
      });
    });
  });

  describe("inspectByte", () => {
    const data = [0x41, 0xFF, 0x00, 0x01, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00];

    it("computes address from base + offset", () => {
      const result = inspectByte(data, 2, "0x1000");
      expect(result["Address"]).toBe("0x1002");
    });

    it("shows offset in hex", () => {
      const result = inspectByte(data, 5, "0x0");
      expect(result["Offset"]).toBe("0x5");
    });

    it("computes UInt8 correctly", () => {
      const result = inspectByte(data, 0, "0x0");
      expect(result["UInt8"]).toBe("65");
    });

    it("computes Int8 for values > 127", () => {
      const result = inspectByte(data, 1, "0x0");
      expect(result["Int8"]).toBe("-1");
    });

    it("computes Hex representation", () => {
      const result = inspectByte(data, 0, "0x0");
      expect(result["Hex"]).toBe("0x41");
    });

    it("computes Binary representation", () => {
      const result = inspectByte(data, 0, "0x0");
      expect(result["Binary"]).toBe("01000001");
    });

    it("shows printable character", () => {
      const result = inspectByte(data, 0, "0x0");
      expect(result["Char"]).toBe("'A'");
    });

    it("shows N/A for non-printable", () => {
      const result = inspectByte(data, 2, "0x0");
      expect(result["Char"]).toBe("N/A");
    });

    it("computes UInt16 LE", () => {
      const result = inspectByte([0x01, 0x02], 0, "0x0");
      expect(result["UInt16 (LE)"]).toBe(String(0x01 | (0x02 << 8)));
    });

    it("computes UInt32 LE", () => {
      const result = inspectByte([0x01, 0x00, 0x00, 0x00], 0, "0x0");
      expect(result["UInt32 (LE)"]).toBe("1");
    });

    it("extracts string until null terminator", () => {
      const result = inspectByte(data, 4, "0x0");
      expect(result["String"]).toBe('"Hello"');
    });
  });
});
