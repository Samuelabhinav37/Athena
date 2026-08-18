import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 3000,
    strictPort: true,
    proxy: {
      "/v1": "http://localhost:8000",
      "/health": "http://localhost:8000",
      "/ready": "http://localhost:8000"
    }
  }
});
