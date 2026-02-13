import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/__tests__/e2e/**/*.test.ts"],
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
