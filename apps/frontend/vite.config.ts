import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/xlsx")) return "xlsx";
          if (id.includes("node_modules/jszip") || id.includes("node_modules/pako")) return "archive-vendor";
          if (id.includes("node_modules/underscore")) return "utility-vendor";
          if (id.includes("node_modules/mammoth") || id.includes("node_modules/entities")) return "document-import";
          if (id.includes("node_modules/reactflow") || id.includes("node_modules/@reactflow")) return "reactflow";
          if (id.includes("node_modules/react") || id.includes("node_modules/react-dom")) return "react-vendor";
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5173
  }
});
