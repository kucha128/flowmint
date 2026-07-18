import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves this build from src-tauri/tauri.conf.json > build.frontendDist.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { target: "es2021", outDir: "dist", emptyOutDir: true },
});
