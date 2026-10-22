import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Everything under /api and /health is proxied to the IAM API so the browser
// talks to a single origin. In Docker the target is the compose service name.
//
// Agent endpoints are NOT proxied: the console calls them directly, because a
// holder proof can only be produced by the agent that owns the private key.
// The agent services allow the console's origin via CORS.
const apiTarget = process.env.VITE_API_TARGET ?? "http://localhost:8000";

const proxy = {
  "/api": { target: apiTarget, changeOrigin: true },
  "/health": { target: apiTarget, changeOrigin: true },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, host: true, proxy },
  preview: { port: 5173, host: true, proxy },
});
