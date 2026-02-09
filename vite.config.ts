import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import fs from "fs";
import type { Plugin } from "vite";

function copyFridaClient(): Plugin {
  const src = path.resolve(
    __dirname,
    "node_modules/frida-web-client-browserify/dist/frida-web-client.browser.js",
  );
  const pubDest = path.resolve(__dirname, "public/frida-web-client.browser.js");

  return {
    name: "copy-frida-client",
    buildStart() {
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, pubDest);
      }
    },
  };
}

export default defineConfig({
  base: "/frida-web/",
  plugins: [react(), tailwindcss(), copyFridaClient()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
