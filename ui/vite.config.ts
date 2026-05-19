import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Build the React bundle directly into the Python package so the wheel
// ships it without any post-build copy step.
const PYTHON_FRONTEND_DIR = resolve(
  __dirname,
  "../src/agentsploit/web/frontend"
);

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  build: {
    outDir: PYTHON_FRONTEND_DIR,
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    // Dev mode: proxy /api to the FastAPI server running on :8800.
    proxy: {
      "/api": "http://127.0.0.1:8800",
    },
  },
});
