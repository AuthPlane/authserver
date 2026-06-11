import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/admin/auth": "http://localhost:9101",
      "/admin/clients": "http://localhost:9101",
      "/admin/users": "http://localhost:9101",
      "/admin/scopes": "http://localhost:9101",
      "/admin/audit": "http://localhost:9101",
      "/admin/stats": "http://localhost:9101",
      "/admin/vault": "http://localhost:9101",
      "/admin/connectors": "http://localhost:9101",
      "/admin/system": "http://localhost:9101",
      "/admin/tokens": "http://localhost:9101",
      "/admin/keys": "http://localhost:9101",
      "/admin/settings": "http://localhost:9101",
      "/admin/resource-servers": "http://localhost:9101",
      "/admin/token-exchange": "http://localhost:9101",
    },
  },
});
