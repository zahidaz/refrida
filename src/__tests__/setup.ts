import "@testing-library/jest-dom/vitest";
import { vi, beforeEach } from "vitest";

const FridaWebMock = {
  Client: vi.fn(),
  TransportLayerSecurity: { Disabled: 0, Enabled: 1 },
  SessionDetachReason: {
    ApplicationRequested: 0,
    ProcessReplaced: 1,
    ProcessTerminated: 2,
    ConnectionTerminated: 3,
    DeviceLost: 4,
  },
};

Object.defineProperty(window, "FridaWeb", {
  value: FridaWebMock,
  writable: true,
});

Object.defineProperty(navigator, "clipboard", {
  value: {
    writeText: vi.fn().mockResolvedValue(undefined),
    readText: vi.fn().mockResolvedValue(""),
  },
  writable: true,
});

if (!URL.createObjectURL) {
  URL.createObjectURL = vi.fn(() => "blob:mock-url");
}
if (!URL.revokeObjectURL) {
  URL.revokeObjectURL = vi.fn();
}

beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});
